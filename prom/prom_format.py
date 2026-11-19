"""Identify an SGI firmware image's container/format.

Standard library only: ``pyirix`` must stay importable without the workspace
(``analysis_tools`` imports ``sgi_workspace``; this module must not). It is the
single low-level detector for "what is this file", used by
:mod:`pyirix.prom.prom_loader` to decide whether an image may be sliced and
disassembled as a MIPS CPU PROM at all.

Rationale: several library images are *not* a flat MIPS PROM — some are a
container that hides the MIPS image at an offset (SN0/SN1 ``JFKSWCSM``, O2/IP32
``SHDR``, IO4 ``JKSW``/``JFK4``), and others are not MIPS at all (x86 BIOS,
68K system controller, ARM transport processor, graphics microcode). Returning
any of them as a flat image based at the CPU-PROM base fabricates a
disassembly; the loader refuses instead (see
``prom_loader.extract_prom_code``).
"""

import struct
from dataclasses import dataclass
from typing import List, Optional

# --- recognised formats -----------------------------------------------------
FORMAT_SN_CONTAINER = "sn-container"   # JFKSWCSM @0x40 (IP27/IP35/IO6)
FORMAT_SHDR = "shdr"                   # "SHDR" @0x08 (IP32/O2, and its flash)
FORMAT_MIPS_ELF = "mips-elf"           # \x7fELF @0 (Venice graphics)
FORMAT_SYSCO_68K = "68k-sysco"         # "ESTFBINR" @0 (Origin L1/L2)
FORMAT_X86_BIOS = "x86-bios"           # \x55\xaa @0 (Voyager/ATI)
FORMAT_KONA_ARM = "kona-arm"           # 0xbadc0ffe @0 (InfiniteReality)
FORMAT_MMSC_X86 = "mmsc-x86"           # 0x5aa5a55a @0x18 (MMSC)
FORMAT_GE_MICROCODE = "ge-microcode"   # "EA\x00\x01" @0 (GE5 GE microcode object)
FORMAT_GE7_MICROCODE = "ge7-microcode" # mconT container 0x966e0001 @0, 26-byte records
FORMAT_HQ3_MICROCODE = "hq3-microcode" # 5120 words, all <= 0x00FFFFFF (Impact HQ3)
FORMAT_GR2_MICROCODE = "gr2-microcode" # MIPS ECOFF object, GR2/Express microcode
FORMAT_VPRO_MICROCODE = "vpro-microcode"  # 12-byte records, bits {0,1,88} reserved (Buzz)
FORMAT_GE11_MICROCODE = "ge11-microcode"  # 12-byte ge_ucode records (GE11/Impact)
FORMAT_UCODE_OBJECT = "ucode-object"   # 'E'|tag @0 + a section table closing at EOF
FORMAT_GE_OBJECT = "ge-object"         # 0x014d0003 @0, .text/.data/.bss table
FORMAT_VOF_TIMING = "vof-timing"       # 0x77229966 @0, VOF timing block
FORMAT_VFC_DATABASE = "vfc-database"   # 0x4 'sdb ' @0, VideoFormatCompiler database
FORMAT_M68K_MODULE = "m68k-module"     # 0x00000107 @0 + self-relative 68K code
FORMAT_PROM_11EE_TABLE = "prom-11ee-table"  # 0x000011ee@0 + (j,nop) entry table
FORMAT_PROM_11EE_CODE = "prom-11ee-code"    # 0x000011ee@0 + MIPS code at +0x20
FORMAT_MIPS_AR_ARCHIVE = "mips-ar-archive"  # !<arch> EB symbol index + ECOFF member
FORMAT_MIPS_ECOFF = "mips-ecoff"       # MIPS ECOFF object, 2+ loaded segments
FORMAT_IO4_JFK4 = "io4-jfk4"           # "JFK4"@0: flat MIPS w/ 0x18 header
FORMAT_IO4_JKSW = "io4-jksw"           # "JKSW"@0: Everest segment table
FORMAT_MIPS_VECTOR = "mips-vector"     # classic SGI CPU PROM (IP4..IP30)
FORMAT_MIPS_VECTOR_SWAPPED = "mips-vector-swapped"  # same, raw flash word-swapped

# Minimum size for a classic (non-swapped) MIPS vector PROM. A real one is at
# least tens of KiB; below this a first-word-only match is a chip dump, not a
# PROM (see is_mips_vector). 4 KiB, vs 8 KiB for the byte-swapped path.
MIN_MIPS_VECTOR_SIZE = 0x1000
FORMAT_TEXT = "text-data"              # plain text / data (not firmware)
FORMAT_SPD_EEPROM = "spd-eeprom"       # JEDEC SDRAM SPD (256 B, multi-field)
FORMAT_EEPROM_VPD = "eeprom-vpd"       # SGI board serial EEPROM (VPD string table)
FORMAT_NVRAM_ENV = "nvram-env"         # SGI firmware environment EEPROM/NVRAM
FORMAT_UNKNOWN = "unknown"

#: Formats that are positively NOT a raw MIPS PROM image, and so must be
#: REFUSED (annotated) rather than disassembled -- presenting flat MIPS for any
#: of these fabricates output. ``sn-container``, ``shdr``, ``io4-jfk4``,
#: ``io4-jksw`` and ``mips-vector`` are images we CAN slice. ``unknown`` is
#: included: an image that fails every positive check cannot be vouched for, so
#: it is refused with a named reason rather than guessed at (the library files
#: that land here are I2C/EEPROM chip dumps, graphics microcode, and
#: controller/EPROM/flash images -- none a CPU PROM).
NON_MIPS_FORMATS = frozenset({
    FORMAT_MIPS_ELF,
    FORMAT_SYSCO_68K,
    FORMAT_X86_BIOS,
    FORMAT_KONA_ARM,
    FORMAT_MMSC_X86,
    FORMAT_GE_MICROCODE,
    FORMAT_GE7_MICROCODE,
    FORMAT_HQ3_MICROCODE,
    FORMAT_GR2_MICROCODE,
    FORMAT_VPRO_MICROCODE,
    FORMAT_GE11_MICROCODE,
    FORMAT_UCODE_OBJECT,
    FORMAT_GE_OBJECT,
    FORMAT_VOF_TIMING,
    FORMAT_VFC_DATABASE,
    FORMAT_M68K_MODULE,
    FORMAT_PROM_11EE_TABLE,
    FORMAT_PROM_11EE_CODE,
    FORMAT_MIPS_AR_ARCHIVE,
    FORMAT_MIPS_ECOFF,
    FORMAT_SPD_EEPROM,
    FORMAT_EEPROM_VPD,
    FORMAT_NVRAM_ENV,
    FORMAT_TEXT,
    FORMAT_UNKNOWN,
})

# O2/IP32 PROM outer container: magic 'PROM' at offset 0, 256-byte header, flash
# data at 0x100 (hw/mips/sgi_o2.c::sgi_o2_strip_prom_container).
PROM_CONTAINER_MAGIC = b'PROM'
PROM_CONTAINER_OFFSET = 0x100
# SHDR flash segment header, measured against hw/mips/sgi_o2.c and the IP32
# flash (irix-657m IP32prom flash.h / libsk flash.c validHdr/validBody). 64-byte
# header on 256-byte page boundaries:
#   reserved(8) @+0x00 | 'SHDR' @+0x08 | segLen @+0x0c
#   | nameLen @+0x10 | vsnLen @+0x11 | segType @+0x12 | aux @+0x13
#   | name[32] @+0x14 | version[8] @+0x34 | header-checksum @+0x3c | body @+0x40
# Both checksums are self-zeroing negated 32-bit big-endian word sums: the
# header sum covers the 15 words before its checksum word, the body sum covers
# the body up to (and including) the segment's last aligned word.
SHDR_SEG_MAGIC = b'SHDR'
SHDR_SEG_PAGE = 256
SHDR_SEG_HDR = 0x40
SHDR_SEG_LEN_OFF = 0x0C
SHDR_SEG_FIELD_OFF = 0x10        # nameLen/u8, vsnLen/u8, segType/u8, aux/u8
SHDR_SEG_NAME_OFF = 0x14
SHDR_SEG_NAME_LEN = 32
SHDR_SEG_VSN_OFF = 0x34
SHDR_SEG_VSN_LEN = 8
SHDR_SEG_HDRSUM_OFF = 0x3C
SHDR_SEG_BODY_OFF = 0x40

# IO4 'JFK4' image: magic@0, -, loadAddr@0x08, size@0x0c, entry@0x10, ver@0x14,
# code@0x18. Established by measurement over the 3 library files (load==entry,
# and size == file_size - 0x18 exactly for each; the code is coherent MIPS).
JFK4_CODE_OFFSET = 0x18
JFK4_LOAD_ADDR = 0x81800000

# IO4 'JKSW' segment-table image (sys/EVEREST/promhdr.h, source-validated):
#   evpromhdr_t @0x00 {magic, cksum, startaddr, length, entry, version}  (24 B)
#   seginfo_t   @0x18 {si_magic='SEG2', si_numsegs, si_segs[NUMSEGS]}
#   promseg_t  (0x30): type, offset, entry, startaddr, length, cksum, data, resv
#   segment data begins at PROMDATA_OFFSET (0x1000).
# NOTE: promhdr.h also defines SEGINFO_OFFSET=0x100, but every library JKSW
# image has si_magic at 0x18 and NOT at 0x100, so the MEASURED offset is used
# (source for the struct, measurement for its location).
JKSW_SI_MAGIC = 0x53454732             # 'SEG2'
JKSW_SEGINFO_OFFSET = 0x18
JKSW_SEG_SIZE = 0x30
JKSW_MAXSEGS = 16
JKSW_STYPE_MASK = 0xFF << 8
JKSW_STYPE_MASTER = 0xFF << 8
JKSW_PROMDATA_OFFSET = 0x1000
JKSW_DESCRIPTION = "IO4 'JKSW' image (Everest promhdr segment table)"

_MAGIC_AT_ZERO = (
    (b'\x7fELF', FORMAT_MIPS_ELF),
    (b'ESTFBINR', FORMAT_SYSCO_68K),
    (b'\x55\xaa', FORMAT_X86_BIOS),
    (b'\xba\xdc\x0f\xfe', FORMAT_KONA_ARM),
    (b'JKSW', FORMAT_IO4_JKSW),
    (b'JFK4', FORMAT_IO4_JFK4),
    (b'EA\x00\x01', FORMAT_GE_MICROCODE),
    # GE7 / HQ3 / GR2 / VPro used to sit here as short byte PREFIXES. Those
    # prefixes were never the invariant: GR2's six bytes `01 60 00 05 2b 91` are
    # literally the ECOFF header fields magic@0|nscns@2|top16(timestamp)@4, so it
    # named one build's timestamp; VPro's eight bytes are one image's first two
    # records; HQ3's three bytes are the first word of one variant. They now go
    # through the structural arms below, which reject a near-miss (see
    # is_gr2_ecoff / is_hq3_microcode / is_ge7_microcode / is_vpro_microcode).
)

_DESCRIPTIONS = {
    FORMAT_SN_CONTAINER: "SN0/SN1 container (JFKSWCSM@0x40; IP27/IP35/IO6)",
    FORMAT_SHDR: "O2/IP32 SHDR container ('SHDR'@0x08)",
    FORMAT_MIPS_ELF: "MIPS ELF image",
    FORMAT_SYSCO_68K: "68K system controller firmware (ESTFBINR)",
    FORMAT_X86_BIOS: "x86 firmware / VGA BIOS (55AA)",
    FORMAT_KONA_ARM: "ARM transport processor firmware (KONA)",
    FORMAT_MMSC_X86: "MMSC controller firmware (x86, 5aa5a55a@0x18)",
    FORMAT_GE_MICROCODE: "GE5 graphics microcode object",
    FORMAT_GE7_MICROCODE: "GE7/GR2 graphics microcode (mconT container)",
    FORMAT_HQ3_MICROCODE: "Impact HQ3/MGRAS graphics microcode",
    FORMAT_GR2_MICROCODE: "GR2/Express graphics microcode (MIPS ECOFF object)",
    FORMAT_VPRO_MICROCODE: "VPro Buzz transform-engine microcode",
    FORMAT_UCODE_OBJECT: "SGI graphics-microcode object ('E'|tag + section table)",
    FORMAT_GE_OBJECT: "GE microcode object (0x014d0003, .text/.data/.bss table)",
    FORMAT_VOF_TIMING: "VOF display-timing block (0x77229966)",
    FORMAT_VFC_DATABASE:
        "VideoFormatCompiler database ('sdb ' container: timing/format table)",
    FORMAT_M68K_MODULE: "68K graphics microcode module (0x00000107)",
    FORMAT_PROM_11EE_TABLE:
        "graphics PROM, 0x000011ee header + (j,nop) entry table",
    FORMAT_PROM_11EE_CODE:
        "graphics PROM, 0x000011ee header + MIPS code at +0x20",
    FORMAT_MIPS_AR_ARCHIVE:
        "MIPS 'ar' archive (EB symbol index + ECOFF member)",
    FORMAT_MIPS_ECOFF:
        "MIPS ECOFF object, loaded sections in 2+ 16 MiB segments",
    FORMAT_IO4_JFK4: "IO4 'JFK4' MIPS image (load 0x81800000, code@0x18)",
    FORMAT_IO4_JKSW: JKSW_DESCRIPTION,
    FORMAT_MIPS_VECTOR: "classic SGI MIPS CPU PROM",
    FORMAT_MIPS_VECTOR_SWAPPED:
        "raw-flash SGI MIPS CPU PROM (16-bit word-swapped)",
    FORMAT_TEXT: "plain text / data (not firmware)",
    FORMAT_SPD_EEPROM: "JEDEC SDRAM SPD EEPROM (256 B)",
    FORMAT_EEPROM_VPD: "SGI board VPD serial EEPROM (24C04/24C512)",
    FORMAT_NVRAM_ENV: "SGI firmware (ARCS) environment EEPROM/NVRAM",
    FORMAT_GE11_MICROCODE: "GE11/MGRAS microcode (12-byte record table)",
    FORMAT_UNKNOWN: "unrecognised firmware (not a MIPS CPU PROM)",
}


def _word(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 4], 'big')


def is_mips_vector(data: bytes) -> bool:
    """True if *data* looks like a classic SGI MIPS PROM (reset vector at 0 or 4).

    Valid reset-vector opcodes (SGI PROMs begin with a jump/branch, sometimes
    after a zero word as on IP28). Used only as a fallback after every magic
    check, so a container whose first word happens to look like MIPS (O2's
    ``0x10000011`` decodes as BEQ) is caught by its magic first.
    """
    # Floor: a real classic SGI PROM is at least tens of KiB. A sub-4KiB file
    # whose first word merely LOOKS like an opcode is far more likely an I2C
    # EEPROM / chip dump. The byte-swapped path below already refuses those on
    # size + jump evidence; without a floor here the loose test accepted a
    # 256-byte 93CS56 EEPROM as a MIPS PROM (measured false positive, 2026-09-28;
    # the smallest real mips-vector file in the library is 32,340 B, so this
    # reclassifies exactly that one chip dump and no real PROM).
    if len(data) < MIN_MIPS_VECTOR_SIZE:
        return False
    valid = {0x02, 0x04, 0x10}   # J, BEQ, COP0 (IP26's cache init)
    # REGIMM (0x01) is deliberately NOT a valid reset vector: a reset
    # entry is a jump/branch/cache-op, never a REGIMM branch. The one library
    # file whose word0 is REGIMM (bins/graphics/vpro/buzz_vpro.bin) is a
    # structured 3-word-record table, not MIPS code — dropping 0x01 refuses it
    # and affects no real PROM (measured: REGIMM is the only opcode used by
    # exactly that one file among 49 mips-vector images).
    w0 = _word(data, 0)
    if (w0 >> 26) & 0x3F in valid:
        # A reset vector that is a JUMP must jump into PROM space. A `J` opcode
        # alone is satisfied by ordinary data constants: three Professional IRIS
        # 070-0093 DATA ROMs have word0 0x0b000b00 -- opcode 2 (J), target
        # 0x0c002c00, which is outside their own 64 KiB image, and the same word
        # repeats 8 of the first 8 words. Measured across the library: this arm
        # selects exactly those 3 files and no real PROM (the 32 genuine J
        # vectors all land in 0x9FC00000.. or 0xBFC00000..). The other opcodes
        # in `valid` -- BEQ (IP54) and COP0 cache-init (IP26) -- carry no
        # absolute target and are unaffected by this test.
        if (w0 >> 26) & 0x3F == 0x02:
            return _jump_into_prom(w0)
        return True
    if _word(data, 0) == 0 and ((_word(data, 4) >> 26) & 0x3F) in valid:
        return True
    return False


def swap_words16(data: bytes) -> bytes:
    """Return *data* with each 16-bit word byte-swapped (raw flash dumps)."""
    n = len(data) & ~1
    out = bytearray(n)
    out[0::2] = data[1:n:2]
    out[1::2] = data[0:n:2]
    return bytes(out)


def _jump_into_prom(word: int) -> bool:
    if (word >> 26) in (0x02, 0x03):        # J, JAL
        target = 0xB0000000 | ((word & 0x03FFFFFF) << 2)
        return (0x9FC00000 <= target < 0xA0000000
                or 0xBFC00000 <= target < 0xC0000000)
    return False


def is_swapped_mips_vector(data: bytes) -> bool:
    """True if *data* is a MIPS PROM stored 16-bit word-swapped (raw flash).

    STRONG evidence only, so an I2C/EEPROM chip dump cannot be mistaken for
    firmware: the file must be at least 8 KiB, byte-swapping each 16-bit word
    must put a jump into PROM space at offset 0 or +4, and that must start a run
    of >= 2 such jumps on the classic 8-byte stride. The loose "does a swap make
    the first word look like MIPS?" test fires on ~25 small chip dumps; this one
    fires only on the genuine image (measured: exactly one file in the library).
    """
    if len(data) < 0x2000:
        return False
    x = swap_words16(data)

    start = None
    for off in (0x00, 0x04):
        if off + 4 <= len(x) and _jump_into_prom(_word(x, off)):
            start = off
            break
    if start is None:
        return False

    count = 0
    off = start
    while off + 4 <= len(x) and off < start + 0x100:
        if not _jump_into_prom(_word(x, off)):
            break
        count += 1
        off += 8
    return count >= 2


def is_text_image(data: bytes) -> bool:
    """True if *data* is essentially printable ASCII (a text/data file).

    Catches the GR2 adjustment files (``adjntsc.bin``/``adjpal.bin``, which are
    literally ``0x..`` hex text) so they are named as text rather than offered
    to a disassembler.
    """
    if len(data) < 16:
        return False
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(data) >= 0.90


# --- VideoFormatCompiler database ('sdb ' container) -------------------------
# One container, three extensions in PROM_library: `.sdb` (26), `.cmb` (4, the
# Kona combination files) and `.vfo` (2, ShotMaker video timing). The extension is
# therefore not the name and is not part of the test; the container says what it
# is. Measured on all 32 files:
#
#   @0x00  u32 4            length prefix covering the fourcc that follows
#   @0x04  "sdb "           the fourcc
#   @0x08  u32 0            reserved
#   @0x0c  u32 1            version
#   @0x10  u32 flags        (0,1) = VideoFormatCompiler .sdb/.vfo,
#   @0x14  u32 flags        (1,0) = Kona video format combination (.cmb)
#   @0x18  u32 producerLen  byte length of the producer record that follows
#   @0x1c  char[producerLen] the producer: "VideoFormatCompiler" (28),
#                            "Kona video format combination file" (4)
#   @0x80  u32 recordCount  size of the trailing record table
#   @0x88  u32 tableEnd     (the table's first record starts at tableEnd + 4)
#   tail   recordCount records, walked BACKWARDS from EOF -- each is
#          nameLen, name[nameLen] padded to 4, type, mid, length (all u32) --
#          and the walk must stop exactly on tableEnd + 4.
VFC_LENGTH_PREFIX = 4
VFC_FOURCC = b'sdb '
VFC_PRODUCER_OFFSET = 0x18       # the u32 length; the string follows at 0x1c
VFC_PRODUCER_LEN_OFFSET = 0x18
VFC_PRODUCER_OFFSET_TEXT = 0x1C
VFC_PRODUCER_MAX = 0x100
VFC_RECORD_COUNT_OFFSET = 0x80
VFC_TABLE_END_OFFSET = 0x88
#: The two measured (flags@0x10, flags@0x14) pairs, by what they select.
VFC_FLAVOURS = {(0, 1): "videoformatcompiler", (1, 0): "kona-combination"}


def vfc_database_record_table(data: bytes) -> tuple:
    """Walk the tail record table BACKWARDS from EOF.

    Returns ``(records, stop)``: ``[(offset, name, type, mid, length)]`` in file
    order and the offset the walk stopped at (0 if it ran off the front). The walk is
    the container's own claim being checked against its bytes: each record's
    ``nameLen`` must be the word at the record's start, the name must be
    identifier-like and the padding after it zero, and the whole table must close
    exactly at the declared end (:data:`VFC_TABLE_END_OFFSET`). Measured on the
    32 held files: 58-182 records each, every name a C identifier (2,698 records,
    no exception), every table closing on its declared end.
    """
    n = len(data)
    end = n
    recs = []
    while end - 16 >= 0:
        found = None
        for name_len in range(1, 64):
            pad = (name_len + 3) & ~3
            start = end - 12 - pad - 4
            if start < 0:
                break
            if _word(data, start) != name_len:
                continue
            name = data[start + 4:start + 4 + name_len]
            if not name or not (name[0:1].isalpha() or name[0:1] == b'_'):
                continue
            if not all(32 <= c < 127 for c in name):
                continue
            if any(data[start + 4 + name_len:start + 4 + pad]):
                continue
            found = (start, name, _word(data, end - 12), _word(data, end - 8),
                     _word(data, end - 4))
            break
        if found is None:
            break
        recs.append(found)
        end = found[0]
    recs.reverse()
    return recs, end


def _vfc_container_and_table(data: bytes) -> Optional[tuple]:
    """Validate the container and return ``(info, records)``, or None.

    The single code path behind :func:`parse_vfc_database` and
    :func:`parse_vfc_fields`: one validation, one walk, so the container's own
    record-count check means the same thing to the decoder as to the detector. If
    the two ever walked separately they could disagree about a file that passes.
    """
    n = len(data)
    if n < 0x100:
        return None
    if _word(data, 0) != VFC_LENGTH_PREFIX or data[4:8] != VFC_FOURCC:
        return None
    if _word(data, 0x08) != 0 or _word(data, 0x0C) != 1:
        return None
    flavour = VFC_FLAVOURS.get((_word(data, 0x10), _word(data, 0x14)))
    if flavour is None:
        return None
    producer_len = _word(data, VFC_PRODUCER_LEN_OFFSET)
    if not 8 <= producer_len <= VFC_PRODUCER_MAX:
        return None
    if VFC_PRODUCER_OFFSET_TEXT + producer_len > n:
        return None
    raw = data[VFC_PRODUCER_OFFSET_TEXT:VFC_PRODUCER_OFFSET_TEXT + producer_len]
    producer = raw.split(b'\x00', 1)[0]
    if len(producer) < 8 or not all(32 <= c < 127 for c in producer):
        return None
    if any(raw[len(producer):]):        # the record is NUL-padded, not garbage
        return None
    count = _word(data, VFC_RECORD_COUNT_OFFSET)
    table_end = _word(data, VFC_TABLE_END_OFFSET)
    if count < 1 or not VFC_PRODUCER_OFFSET_TEXT + producer_len <= table_end < n:
        return None
    walked = vfc_database_record_table(data)
    recs, stop = walked
    if len(recs) != count or stop != table_end + 4:
        return None
    return ({"flavour": flavour, "producer": producer.decode('ascii'),
             "records": len(recs), "table_end": table_end}, recs)


def parse_vfc_database(data: bytes) -> Optional[dict]:
    """Decode a VideoFormatCompiler ('sdb ') database container, or None.

    Every condition is a field of the container checked against the file's own
    bytes -- there is no string search and no filename in it:

      * the length-prefixed fourcc at 0 (u32 4 then ``"sdb "``);
      * the two header words at 0x08/0x0c (reserved 0, version 1);
      * the flag pair at 0x10/0x14, one of the two measured flavours;
      * a length-prefixed producer record at 0x18/0x1c: printable, NUL-padded
        to its declared length, and at least 8 characters;
      * the trailing record table, which must contain exactly the declared
        number of records and close exactly on the declared end.
    """
    got = _vfc_container_and_table(data)
    return None if got is None else got[0]


def is_vfc_database(data: bytes) -> bool:
    """True if *data* is a VideoFormatCompiler database ('sdb ' container)."""
    return parse_vfc_database(data) is not None


#: Type code -> element width in bytes for the types whose element type the
#: corpus establishes. Type 15 is a length-prefixed string and has no fixed
#: element width; a type absent from this table is returned raw, never guessed.
VFC_TYPE_WIDTHS = {2: 4, 7: 4, 10: 4, 16: 4, 17: 8}
VFC_TYPE_STRING = 15


@dataclass(frozen=True)
class VfcField:
    """One decoded field of a ``vfc-database`` record table.

    ``offset`` is the record's own ``length`` word: where its data lives in the
    file, not where its record lives in the table. ``width`` is the number of
    bytes the decode consumed there and ``count`` the number of elements (1 for a
    scalar, 0 when the field was not decoded). ``value`` is the typed value for a
    decoded field, and the raw bytes for one whose declared type or width the
    file's own layout does not establish -- :attr:`decoded` tells the two apart,
    so a caller can never mistake raw bytes for a number.
    """

    name: str
    type: int
    mid: int
    offset: int
    width: int
    count: int
    value: object

    @property
    def decoded(self) -> bool:
        """True if :attr:`value` is a typed value rather than raw bytes."""
        return self.count > 0


def _vfc_data_extents(records: list) -> dict:
    """``{offset: byte length}`` for every data offset in the record table.

    The layout is measured, not assumed: each data item runs from its own
    ``length`` word to the next item's, and the last one to the first record of
    the table. So the extent is the file's own statement of how wide the item is,
    which is what a decode is checked against -- a declared width that disagrees
    with it is returned raw rather than truncated or over-read.
    """
    offsets = sorted({r[4] for r in records})
    table_start = records[0][0]
    out = {}
    for i, off in enumerate(offsets):
        nxt = offsets[i + 1] if i + 1 < len(offsets) else table_start
        out[off] = nxt - off
    return out


def _vfc_decode(typ: int, mid: int, data: bytes, offset: int,
                avail: int) -> Optional[tuple]:
    """``(value, width, count)`` for one record, or None if it does not decode.

    The rules, all measured over the 3,083 records of the 32 held files:

      * type 15 -- ``u32 len`` then ``len`` printable ASCII bytes (``len == 0``
        is a real empty string: the four ``.cmb`` files carry five of them);
      * types 2/7/10/16/17 -- ``mid`` is the element count: 0 means the field is a
        single scalar of the type's width (so ``MajorVersion``, type 7 mid 0, is
        one u32), and ``mid >= 1`` means ``u32 count`` (equal to ``mid`` on every
        measured record) followed by ``count`` elements of that width
        (u32/u32/u32/float/double).

    The layout check is an upper bound, not an equality: a data item never
    overlaps the next one, so ``offset + width <= extent``. It is not an
    equality because the gaps are real -- ``FormatInfo_F_0_V_FrontPorch`` is one
    u32 with 8 bytes before the next item, and a ``VCHardwareName`` string is 18
    bytes in a 20-byte slot. A declared width that does not fit its extent means
    the rule is not this record's layout, so the answer is None and the caller
    keeps the raw bytes.
    """
    if typ == VFC_TYPE_STRING:
        if avail < 4:
            return None
        length = _word(data, offset)
        if 4 + length > avail or offset + 4 + length > len(data):
            return None
        text = data[offset + 4:offset + 4 + length]
        if not all(32 <= c < 127 for c in text):
            return None
        return text.decode('ascii'), 4 + length, 1
    elem = VFC_TYPE_WIDTHS.get(typ)
    if elem is None:
        return None
    if mid:
        if avail < 4:
            return None
        count = _word(data, offset)
        if count < 1 or count != mid:
            return None
        width = 4 + count * elem
        if width > avail or offset + width > len(data):
            return None
        body = data[offset + 4:offset + width]
        if typ == 17:
            values = list(struct.unpack('>%dd' % count, body))
        elif typ == 16:
            values = list(struct.unpack('>%df' % count, body))
        else:
            values = list(struct.unpack('>%dI' % count, body))
        return values, width, count
    if elem > avail or offset + elem > len(data):
        return None
    body = data[offset:offset + elem]
    if typ == 17:
        return struct.unpack('>d', body)[0], avail, 1
    if typ == 16:
        return struct.unpack('>f', body)[0], avail, 1
    return int.from_bytes(body, 'big'), avail, 1


def parse_vfc_fields(data: bytes) -> Optional[dict]:
    """Decode a ``vfc-database`` container's field table, or None if not one.

    The same validation and the same record-table walk as
    :func:`parse_vfc_database` -- one code path, so the container's own declared
    record count means the same thing to the reader as to the detector.

    Returns ``{"flavour", "producer", "records", "table_end", "fields",
    "values"}``: ``fields`` maps each field name to its
    :class:`VfcField` (type, ``mid``, data offset, width, count, value) and
    ``values`` maps the same names to their values alone. A field whose declared
    type or width the file's own layout does not establish is returned with its
    raw bytes and its type code (``VfcField.decoded`` is False), never with a
    guessed width. Field names are unique over all 32 held files; were a file to
    repeat one, the first occurrence is kept.
    """
    got = _vfc_container_and_table(data)
    if got is None:
        return None
    info, records = got
    extents = _vfc_data_extents(records)
    fields = {}
    for _start, raw_name, typ, mid, offset in records:
        name = raw_name.decode('latin1')
        if name in fields:
            continue
        avail = extents.get(offset, 0)
        decoded = _vfc_decode(typ, mid, data, offset, avail) if avail else None
        if decoded is None:
            fields[name] = VfcField(name, typ, mid, offset, 0, 0,
                                    data[offset:offset + avail])
        else:
            value, width, count = decoded
            fields[name] = VfcField(name, typ, mid, offset, width, count, value)
    return {"flavour": info["flavour"], "producer": info["producer"],
            "records": info["records"], "table_end": info["table_end"],
            "fields": fields,
            "values": {name: f.value for name, f in fields.items()}}


#: JEDEC SPD DRAM device-type codes (byte 2): FPM/EDO/PSDRAM/SDRAM families.
_SPD_DRAM_TYPES = frozenset({0x01, 0x02, 0x03, 0x04, 0x07})


def is_spd_eeprom(data: bytes) -> bool:
    """True if *data* is a JEDEC SDRAM SPD EEPROM image (256 bytes).

    A multi-field STRUCTURAL test, not a single magic: byte0 = number of bytes
    used (0x80), byte2 = DRAM device type, byte3 = row address bits, byte4 =
    column address bits, byte5 = module ranks. Several INDEPENDENT standard SPD
    fields must agree, so a coincidental match is very unlikely. Measured on the
    seven SPD images in PROM_library: all decode to SDRAM with row=13 and
    columns=11 (1 GB) / 10 (512 MB), matching their part numbers."""
    if len(data) != 256 or data[0] != 0x80:
        return False
    if data[2] not in _SPD_DRAM_TYPES:
        return False
    if not (0x0B <= data[3] <= 0x10):      # row address bits
        return False
    if not (0x08 <= data[4] <= 0x0C):      # column address bits
        return False
    if data[5] not in (1, 2, 4):           # module banks / ranks
        return False
    return True


#: SGI board VPD (vital product data) serial-EEPROM images.
#: The string table is a sequence of 0xC0|len markers each followed by exactly
#: ``len`` printable-ASCII bytes (measured on every 24C04 image in PROM_library).


def _vpd_string_records(data: bytes) -> List[bytes]:
    """Decode the 0xC0|len length-prefixed ASCII records of an SGI VPD table."""
    out: List[bytes] = []
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c >= 0xC0:
            length = c & 0x3F
            seg = data[i + 1:i + 1 + length]
            if length >= 1 and len(seg) == length and \
                    all(0x20 <= b < 0x7F for b in seg):
                out.append(seg)
                i += 1 + length
                continue
        i += 1
    return out


def _is_vpd_part_record(seg: bytes) -> bool:
    """True for a ``030_xxx_xxx`` (or ``ddd_dddd_ddd``) part-number record."""
    return (len(seg) == 12 and seg[3:4] == b"_" and seg[8:9] == b"_"
            and seg[0:3].isdigit() and seg[4:8].isdigit()
            and seg[9:12].isdigit())


def is_eeprom_vpd(data: bytes) -> bool:
    """True if *data* is an SGI board VPD serial-EEPROM image.

    A multi-field STRUCTURAL test, not a single magic. Two measured forms:

    * a 24C04 (512 B) board EEPROM: byte0 = 0x00 and the SGI VPD string table is
      present (>= 4 ``0xC0|len`` length-prefixed ASCII records) including the
      ``030_xxx_xxx`` part-number record. Measured on all seven 24C04 images in
      PROM_library: each decodes the same field set (vendor, board, serial,
      part number, revision).
    * a 24C512 (64 KiB) board EEPROM: magic 0x669955aa at offset 0.

    Neither is a CPU PROM; both are refused by the loader (correctly named).
    """
    if len(data) == 512 and data[0] == 0x00:
        records = _vpd_string_records(data)
        if len(records) >= 4 and any(_is_vpd_part_record(r) for r in records):
            return True
    if len(data) == 0x10000 and data[:4] == b"\x66\x99\x55\xaa":
        return True
    return False


#: GE11 (Impact/MGRAS) microcode image: an address table of ``ge_ucode``
#: records (in-tree struct: unsigned short uword2 + pad + two uint32 = 12 bytes),
#: zero-filled at the unused low addresses. Measured on all three images in
#: PROM_library (ge11, ge11_revB, ge11_impact): size is a multiple of 12, the
#: first 24 bytes (addresses 0..1) are zero, and the first written record
#: carries the signature below.
_GE11_UCODE_MAGIC = b"\x8c\xf8\x00\x00\xf9\xc0\x07\xc8"


def is_ge11_microcode(data: bytes) -> bool:
    """True if *data* is a GE11/MGRAS microcode image (12-byte record table)."""
    if len(data) < 0x10000 or len(data) % 12 != 0:
        return False
    if data[0:0x18] != b"\x00" * 0x18:
        return False
    return data[0x18:0x20] == _GE11_UCODE_MAGIC


#: SGI firmware (ARCS) environment EEPROM / NVRAM. The FULLHOUSE IO backplane
#: 93CS56 is one: stored 16-bit word-swapped, it contains the ARCS environment
#: (mem, dksc, scsi(%d)disk(%d), nuunix, debugport, 9600 baud, PST8PDT,
#: init_env()). A single very distinctive token is enough -- no CPU PROM carries
#: the ``scsi(%d)disk(%d)`` device-path template.
_ENV_STRONG = b"scsi(%d)disk(%d)"
_ENV_TOKENS = (b"dksc", b"init_env(", b"nuunix", b"debugport", b"volhdr",
               b"console=", b"mem=")


def _pair_swap(data: bytes) -> bytes:
    """Adjacent-byte (16-bit word) swap, undoing a word-swapped EEPROM dump."""
    return b"".join(data[i:i + 2][::-1] for i in range(0, len(data) - 1, 2))


def is_nvram_env(data: bytes) -> bool:
    """True if *data* is an SGI firmware environment EEPROM/NVRAM image."""
    if len(data) > 0x10000:
        return False
    for cand in (data, _pair_swap(data)):
        if _ENV_STRONG in cand:
            return True
        if sum(1 for t in _ENV_TOKENS if t in cand) >= 3:
            return True
    return False


# --- graphics-microcode families, from DECODED STRUCTURE --------------------
#
# Every arm below reads fields the image itself carries (a magic plus the record
# geometry it declares, a section table, a reserved-bit mask). None of them reads
# a filename, and none of them accepts a short byte prefix on its own: each was
# calibrated against the whole 1073-file PROM_library corpus, and the controls
# are in tests/test_prom_format.py (a near-miss of the same SIZE and a
# random-byte blob are both refused).

def _ieee_single(raw: bytes) -> float:
    """Decode a 4-byte big-endian IEEE-754 single (NaN for a non-finite pattern)."""
    return struct.unpack('>f', raw)[0]


def _never_set_bits(data: bytes, record: int, min_records: int) -> Optional[List[int]]:
    """Bit positions never set in any ``record``-byte big-endian word, or None.

    A microcode ISA leaves its reserved/illegal encodings at zero, so the set of
    bits that never appear set is a content signature that a byte prefix cannot
    give (a prefix names one build; a reserved-bit mask spans the family). The
    control that makes this a measurement rather than a coincidence: random
    bytes of the same size leave NO bit unset, so an empty set never matches.
    """
    n = len(data)
    if record <= 0 or n % record or n < record * min_records:
        return None
    count = [0] * (record * 8)
    for i in range(n // record):
        value = int.from_bytes(data[i * record:(i + 1) * record], 'big')
        for bit in range(record * 8):
            if value >> (record * 8 - 1 - bit) & 1:
                count[bit] += 1
    return [b for b in range(record * 8) if count[b] == 0]


#: GE11/MGRAS microcode instruction format: 96-bit instructions, 10 reserved bits.
GE11_RESERVED_BITS = frozenset({65, 69, 71, 73, 75, 78, 82, 83, 85, 87})
#: VPro Buzz XFORM instruction format: every bit of the two leading bytes is 0
#: (bits 0..15) and bit 88 is reserved. Measured on the held image.
VPRO_RESERVED_BITS = frozenset({0, 1, 88})
#: GE11's second record: the first two address slots are zero-filled and this is
#: the first written instruction (the reset row, seen in all three held images).
_GE11_FIRST_RECORD = b"\x8c\xf8\x00\x00\xf9\xc0\x07\xc8"


def is_ge11_microcode(data: bytes) -> bool:
    """True if *data* is a GE11/MGRAS microcode image (12-byte record table).

    GE11 is downloaded as 96-bit instructions (``len /= 12``,
    ``GE11_UCODE_BASE = 0x200000``) so the record stride is the loader's own
    arithmetic. Evidence, all from the image: size is a multiple of 12, the two
    low address slots are zero-filled (the table is indexed from 0 upward), the
    first written record is the reset row, and the instruction format leaves
    exactly :data:`GE11_RESERVED_BITS` never set across the whole image.
    """
    if len(data) < 0x10000 or len(data) % 12:
        return False
    if data[0:0x18] != b"\x00" * 0x18:
        return False
    if data[0x18:0x20] != _GE11_FIRST_RECORD:
        return False
    never = _never_set_bits(data, 12, 256)
    return never is not None and GE11_RESERVED_BITS <= set(never)


def is_vpro_microcode(data: bytes) -> bool:
    """True if *data* is VPro (Odyssey) Buzz transform-engine microcode.

    The Buzz XFORM image is a table of 12-byte big-endian microcode records.
    Evidence, all from the image: the size is a multiple of 12, the instruction
    format leaves exactly :data:`VPRO_RESERVED_BITS` never set, and the dominant
    control value of the third word is ``0x0008`` in the high half (the record
    type the loader streams). The reserved set is the load-bearing part -- an
    arbitrary 12-byte-strided blob leaves NO bit unset.
    """
    n = len(data)
    if n < 0x2000 or n % 12:
        return False
    never = _never_set_bits(data, 12, 128)
    if never is None or set(never) != VPRO_RESERVED_BITS:
        return False
    records = n // 12
    op8 = sum(1 for i in range(records)
              if data[i * 12 + 8:i * 12 + 10] == b"\x00\x08")
    return op8 / records >= 0.40


def is_hq3_microcode(data: bytes) -> bool:
    """True if *data* is an Impact HQ3/MGRAS command-processor microcode image.

    HQ3 is downloaded by ``MgrasDownloadHQ3Ucode`` as a flat
    ``hquc[jj] = word`` loop with the read-back comparison masked to
    ``0xffffff``: 5,120 words with only 24 bits significant. Both halves of that
    are structural, so the test is the size AND the significance mask -- a
    same-size blob with a non-zero top byte is refused.
    """
    if len(data) != 0x5000:
        return False
    return not any(data[4 * i] for i in range(len(data) // 4))


_GE7_MCONT_MAGIC = 0x966E       # 'mconT' record container, version 1 at +2
_GE7_RECORD = 26                # u16 address + 20 B payload + 2 x u16 spare


def is_ge7_microcode(data: bytes) -> bool:
    """True if *data* is a GE7/GR2 microcode image in the ``mconT`` container.

    ``Gr2DownloadGE7`` reads a header whose magic distinguishes GE7 from HQ2
    (``GE7_MAGIC``/``HQ2_MAGIC``) and then consumes the code as fixed 26-byte
    records (``(length + 6) / sizeof(short) == 13`` shorts: a 2-byte address, a
    20-byte 103-bit-plus-control payload, and two spare shorts). Four claims have
    to agree, and the container's own header supplies three of them:

    * the payload length divides exactly by the declared record stride;
    * record 0 carries address 0 -- the loader writes the 512-word constant pool
      to ``shram[0..511]`` BEFORE the code, so the table starts at slot 0;
    * at least one record carries the ``0xffff`` block terminator;
    * the leading constant pool decodes as finite, plausibly-scaled floats (509
      of the first 512 do in every held image).

    The magic alone is not the evidence: the same 16 header bytes over a random
    body fail the address, terminator and float tests (measured; the control is
    in ``tests/test_prom_format.py``).
    """
    n = len(data)
    if n < 0x100:
        return False
    if int.from_bytes(data[0:2], 'big') != _GE7_MCONT_MAGIC:
        return False
    if int.from_bytes(data[2:4], 'big') != 1:       # container version
        return False
    code_off = int.from_bytes(data[8:12], 'big')
    if not 0x20 <= code_off < n:
        return False
    if (n - code_off) % _GE7_RECORD:
        return False
    records = (n - code_off) // _GE7_RECORD
    if int.from_bytes(data[code_off:code_off + 2], 'big') != 0:
        return False
    has_terminator = False
    good_floats = 0
    for i in range(min(records, 512)):
        base = code_off + _GE7_RECORD * i
        if int.from_bytes(data[base:base + 2], 'big') == 0xFFFF:
            has_terminator = True
        value = _ieee_single(data[base + 2:base + 6])
        if value == value and abs(value) < 1e6:
            good_floats += 1
    if not has_terminator:
        # the terminator may sit past the constant pool
        has_terminator = any(
            int.from_bytes(data[code_off + _GE7_RECORD * i:
                                code_off + _GE7_RECORD * i + 2], 'big') == 0xFFFF
            for i in range(records))
    return has_terminator and good_floats >= 480


#: MIPS ECOFF ``filehdr.f_magic`` values: 0x0160 = MIPSEB, plus the other MIPS
#: variants. The GR2/Express and Impact microcode images are ECOFF OBJECTS, not
#: flat microcode: a ``.text``/``.rdata``/``.data``/``.sdata``/``.bss`` section
#: table is what the ROM loader reads to place each block.
_ECOFF_MAGICS = frozenset({0x0160, 0x0162, 0x0163, 0x0164, 0x0166, 0x0168, 0x016A})
_ECOFF_SECTION_NAMES = frozenset({
    b'.text', b'.rdata', b'.rodata', b'.data', b'.bss', b'.init', b'.fini',
    b'.liblist', b'.sdata', b'.sbss', b'.lit4', b'.lit8', b'.ctors', b'.dtors',
    b'.reginfo', b'.mdebug', b'.comment', b'.lib', b'rsrc',
})
#: Sections whose contents live in the file. ``.bss``/``.sbss`` are uninitialised
#: by definition, so a zero ``scnptr`` there is correct rather than truncation.
_ECOFF_FILE_SECTIONS = frozenset({
    b'.text', b'.rdata', b'.rodata', b'.data', b'.init', b'.fini', b'.liblist',
    b'.sdata', b'.lit4', b'.lit8', b'.ctors', b'.dtors',
})


@dataclass
class EcoffSection:
    """One MIPS ECOFF section header (``scnhdr``, 40 bytes) as decoded."""
    name: bytes
    paddr: int
    vaddr: int
    size: int
    scnptr: int


#: Chain window for a MIPS ECOFF object's loaded sections. A linked SGI object
#: with a ``.init`` section puts ``.text``/``.init`` in one 16 MiB segment
#: (0x004xxxxx) and ``.rdata``/``.data``/``.sdata`` in another (0x1000xxxx), so
#: the sections chain END-TO-START WITHIN a segment, not across the whole file.
ECOFF_SEGMENT = 1 << 24


def _ecoff_loaded(sections: List[EcoffSection]) -> List[EcoffSection]:
    """Sections whose contents live in the file, in table order."""
    return [s for s in sections if s.name in _ECOFF_FILE_SECTIONS]


def parse_ecoff_sections(data: bytes) -> Optional[List[EcoffSection]]:
    """Decode a MIPS ECOFF object's section table, or None if it is not one.

    The layout is the standard ``filehdr`` + optional header + ``scnhdr[]``:
    magic@0, ``f_nscns``@2, ``f_symptr``@8, ``f_nsyms``@12, ``f_opthdr``@16, and
    each 40-byte section header carries name[8], paddr, vaddr, size, scnptr.
    Returns the sections only when the table is INTERNALLY CONSISTENT: a
    ``.text`` first, every section name a real SGI section, and the loaded
    sections chained end-to-start IN ADDRESS ORDER WITHIN EACH 16 MiB SEGMENT.
    That is the evidence; the magic alone is not enough to call an image an
    object.

    The chain test used to span the whole file, which wrongly refused every
    object whose ``.text``/``.init`` pair sits at 0x0040xxxx and whose data
    sections sit at 0x1000xxxx -- three held images (``bins/unknown/te_38a3e8ac.u``,
    ``bins/graphics/re/1280x1024_60_68f3c182.u``,
    ``bins/graphics/re/1600x1200_60_48cdaae3.u``). The per-segment rule accepts
    22 corpus files where the flat rule accepted 19, and the 19 are a strict
    SUBSET of the 22 (measured; no file loses acceptance). A table whose chain
    breaks INSIDE one segment is still refused.
    """
    n = len(data)
    if n < 0x4C:
        return None
    if int.from_bytes(data[0:2], 'big') not in _ECOFF_MAGICS:
        return None
    nscns = int.from_bytes(data[2:4], 'big')
    opthdr = int.from_bytes(data[16:18], 'big')
    if not 1 <= nscns <= 30 or opthdr not in (0, 0x38):
        return None
    base = 20 + opthdr
    if base + nscns * 40 > n:
        return None
    sections = []
    for i in range(nscns):
        off = base + i * 40
        sections.append(EcoffSection(
            name=data[off:off + 8].rstrip(b'\x00 '),
            paddr=int.from_bytes(data[off + 8:off + 12], 'big'),
            vaddr=int.from_bytes(data[off + 12:off + 16], 'big'),
            size=int.from_bytes(data[off + 16:off + 20], 'big'),
            scnptr=int.from_bytes(data[off + 20:off + 24], 'big'),
        ))
    names = [s.name for s in sections]
    if names[0] != b'.text' or not all(nm in _ECOFF_SECTION_NAMES for nm in names):
        return None
    loaded = _ecoff_loaded(sections)
    if not loaded:
        return None
    prev = None
    for s in loaded:
        if not s.size:
            continue
        if prev is not None and (s.vaddr // ECOFF_SEGMENT) == \
                (prev.vaddr // ECOFF_SEGMENT):
            if prev.vaddr + prev.size != s.vaddr:
                return None
        prev = s
    if not all(s.scnptr >= base + nscns * 40 for s in loaded if s.size):
        return None
    return sections


def ecoff_segments(sections: List[EcoffSection]) -> List[int]:
    """Sorted 16 MiB segment indices that hold a loaded section's contents."""
    return sorted({s.vaddr // ECOFF_SEGMENT for s in _ecoff_loaded(sections) if s.size})


def is_gr2_microcode(data: bytes) -> bool:
    """True if *data* is a GR2/Express graphics-microcode MIPS ECOFF object.

    This replaces the six-byte prefix ``01 60 00 05 2b 91`` the detector used to
    match. Those bytes are not a format signature -- they are three ECOFF header
    FIELDS: ``f_magic`` 0x0160, ``f_nscns`` 5, and the top half of the build
    timestamp at +4. The prefix therefore only matched one build with five
    sections, and it missed one-section objects entirely. The structural test
    accepts any consistent MIPS ECOFF object whose loaded sections chain, which
    is what "GR2 microcode" actually is.

    Held images are SHORT: their section table advertises more bytes than the
    file carries (the microcode was extracted from an executable, not from a
    complete on-disk object). The detector names the format from the table, which
    is what the image declares about itself, and the decode layer refuses it --
    so a truncated object is still never disassembled as a PROM.

    ``gr2-microcode`` names the SINGLE-SEGMENT objects (all 18 held images: the
    microcode itself, loaded at 0x00000000 or 0x10000000). An object that spans
    2+ segments is a linked object rather than a microcode block and is named
    ``mips-ecoff`` by :func:`is_mips_ecoff` instead.
    """
    sections = parse_ecoff_sections(data)
    return sections is not None and len(ecoff_segments(sections)) == 1


def is_mips_ecoff(data: bytes) -> bool:
    """True if *data* is a linked MIPS ECOFF object spanning 2+ segments.

    A linked object carries its own ``.init`` (so ``.text`` + ``.init`` fill one
    16 MiB segment) and its data sections in a second segment at 0x10000000;
    the three held examples are ``bins/unknown/te_38a3e8ac.u`` (8 sections,
    ``.text``@0x00400190/.data@0x100006c0) and two truncated 10-section objects
    under ``bins/graphics/re``. Keeping this a SEPARATE name is the point: the 18
    images already classified ``gr2-microcode`` keep that verdict, and the
    segment layout is what the two names disagree about.
    """
    sections = parse_ecoff_sections(data)
    return sections is not None and len(ecoff_segments(sections)) >= 2


#: SGI graphics-microcode OBJECT (the 'µasm' / 'vidasm' / 'vofc' output format).
#: word0 = 'E' (0x45) | section-tag << 8 | u16 version, then a u32 at +4 giving
#: the byte length of a table of (file offset, length) section records. Record 0
#: is the identity string; the remaining records are code and data; the extents
#: are chained in order and the last one closes on EOF. Header size follows the
#: version (20 bytes for v1, 44 for v3).
_UCODE_OBJECT_HDR = {1: 20, 3: 44}


def parse_ucode_object(data: bytes):
    """Decode the section table of an SGI graphics-microcode object, or None.

    Returns ``(version, tag, sections, identity)`` where ``sections`` is the list
    of ``(offset, length)`` records in file order. The acceptance conditions are
    the file's own claims being mutually consistent -- every record in bounds
    and positive, the records CHAINED end-to-start, the first record starting
    exactly at the header's end, and the last closing at EOF (up to 3 bytes of
    odd-length padding) -- plus a printable identity string. A near-miss fails at
    least one of these; a random blob cannot satisfy them.
    """
    n = len(data)
    if n < 24 or data[0:1] != b'E':
        return None
    version = int.from_bytes(data[2:4], 'big')
    hdr = _UCODE_OBJECT_HDR.get(version)
    if hdr is None or hdr > n:
        return None
    if int.from_bytes(data[4:8], 'big') != hdr:
        return None
    sections: List[tuple] = []
    for i in range((hdr - 4) // 8):
        off = int.from_bytes(data[4 + 8 * i:8 + 8 * i], 'big')
        length = int.from_bytes(data[8 + 8 * i:12 + 8 * i], 'big')
        if (off, length) == (0, 0):
            break
        if off <= 0 or length <= 0 or off + length > n:
            return None
        if sections and off != sections[-1][0] + sections[-1][1]:
            return None
        sections.append((off, length))
    if len(sections) < 2 or sections[0][0] != hdr:
        return None
    if not 0 <= n - (sections[-1][0] + sections[-1][1]) <= 3:
        return None
    ident = data[sections[0][0]:sections[0][0] + sections[0][1]]
    if not ident:
        return None
    printable = sum(1 for c in ident if c == 0 or 9 <= c < 127)
    if printable / len(ident) < 0.95:
        return None
    if sum(1 for c in ident if 65 <= c < 123) < 3:
        return None
    return version, data[1], sections, ident


def is_ucode_object(data: bytes) -> bool:
    """True if *data* is an SGI graphics-microcode object ('E'|tag container)."""
    return parse_ucode_object(data) is not None


def _ge_object_sections(data: bytes):
    """Decode a ``0x014d0003`` GE microcode object's section table, or None.

    The header is ``u32 0x014d0003`` then four zero words, and the section table
    starts at +0x38 with 40-byte records: ``name[8]``, then four u32 fields --
    physical address, virtual address, size and file offset. The names are the
    standard ``.text``/``.data``/``.bss`` triple and every section that HAS a file
    image starts at or after the table's end and chains end-to-start in file
    order. That is the evidence; the magic alone is not enough.
    """
    n = len(data)
    if n < 0x100 or int.from_bytes(data[0:4], 'big') != 0x014D0003:
        return None
    base, stride = 0x38, 40
    sections = []
    for i in range(8):
        off = base + i * stride
        if off + stride > n:
            break
        name = data[off:off + 8].rstrip(b'\x00')
        if not name or name[0:1] != b'.' or not all(32 <= c < 127 for c in name):
            break
        paddr, vaddr, size, foff = (
            int.from_bytes(data[off + 8 + 4 * k:off + 12 + 4 * k], 'big')
            for k in range(4))
        sections.append(EcoffSection(name=name, paddr=paddr, vaddr=vaddr,
                                     size=size, scnptr=foff))
    if len(sections) < 2 or sections[0].name != b'.text':
        return None
    loaded = [s for s in sections if s.scnptr]
    if not loaded:
        return None
    if not all(s.scnptr >= base + len(sections) * stride for s in loaded):
        return None
    if not all(loaded[i].scnptr + loaded[i].size == loaded[i + 1].scnptr
               for i in range(len(loaded) - 1)):
        return None
    return sections


def is_ge_object(data: bytes) -> bool:
    """True if *data* is a GE microcode object in the ``0x014d0003`` container.

    A distinct flavour from the ECOFF objects: same idea (a named section table
    that says where each block goes) but a different, 40-byte record layout and a
    different magic. Six held images use it, all with the ``.text/.data/.bss``
    triple and chained file images.
    """
    return _ge_object_sections(data) is not None


def vof_timing_run_lengths(data: bytes):
    """Return ``(distinct_values, max_run, mean_run)`` for a VOF timing block.

    A VOF block is a header plus a byte-oriented DISPLAY TIMING table: runs of the
    same byte value (a scanline count, a blanking duration, a sync width). The
    signature is therefore run structure, not a value set -- random bytes of the
    same size give a maximum run of 2 and a mean of 1.01, while every held VOF
    table has a maximum run of 33 and a mean of 1.8-1.9.
    """
    body = data[8:]
    if not body:
        return None
    runs = []
    current = 1
    for prev, cur in zip(body, body[1:]):
        if cur == prev:
            current += 1
        else:
            runs.append(current)
            current = 1
    runs.append(current)
    return len(set(body)), max(runs), sum(runs) / len(runs)


def is_vof_timing(data: bytes) -> bool:
    """True if *data* is a VOF display-timing block (magic ``0x77229966``).

    Requires the magic, a plausible size, and the run structure above -- at least
    one run of 8 or more identical bytes and a mean run length of 1.5 or more.
    A random same-size body with the magic stamped on it is refused.
    """
    n = len(data)
    if n < 0x100 or n > 0x8000:
        return False
    if int.from_bytes(data[0:4], 'big') != 0x77229966:
        return False
    got = vof_timing_run_lengths(data)
    if got is None:
        return False
    _distinct, max_run, mean_run = got
    return max_run >= 8 and mean_run >= 1.5


#: 68K absolute control-transfer opcodes used to test a graphics microcode
#: module's own declared load address (``JSR <abs.l>`` / ``JMP <abs.l>``).
_M68K_JSR_ABSL = 0x4EB9
_M68K_JMP_ABSL = 0x4EF9
_M68K_CODE_OFFSET = 0x20
_M68K_MIN_TARGETS = 64


def m68k_module_targets(data: bytes):
    """Return ``(load_address, targets, inside)`` for a 68K graphics module.

    Some graphics boards carry a 68K microcontroller whose microcode module is a
    header followed by position-dependent 68K code. The header is
    ``0x00000107`` @0, a code size @4 and the module's own LOAD ADDRESS @28. The
    test is not the magic (12 files share it and so could a coincidental blob):
    it is that the code's absolute ``JSR``/``JMP`` targets land inside
    ``[load, load + len)``. Measured on the 12 held images, 564-626 targets each
    and 100% of them inside; the same header over a RANDOM body yields no
    in-range targets at all (the control in tests/test_prom_format.py).
    """
    n = len(data)
    if n < 0x1000 or int.from_bytes(data[0:4], 'big') != 0x00000107:
        return None
    load = int.from_bytes(data[28:32], 'big')
    if load < 0x1000:
        return None
    words = (n - _M68K_CODE_OFFSET) // 2
    targets = inside = 0
    for i in range(words - 2):
        off = _M68K_CODE_OFFSET + 2 * i
        if int.from_bytes(data[off:off + 2], 'big') in (_M68K_JSR_ABSL, _M68K_JMP_ABSL):
            target = int.from_bytes(data[off + 2:off + 6], 'big')
            targets += 1
            if load <= target < load + n:
                inside += 1
    return load, targets, inside


def is_m68k_module(data: bytes) -> bool:
    """True if *data* is a position-dependent 68K graphics-microcode module."""
    got = m68k_module_targets(data)
    if got is None:
        return False
    _load, targets, inside = got
    return targets >= _M68K_MIN_TARGETS and inside == targets


#: SGI graphics-board PROMs (Impact MG1, Reality-Engine GE8/GE10) carry their own
#: 16-byte header: ``0x000011ee``@0, the BOARD'S OWN CAPACITY@4 (0x00020000 for a
#: 128 KiB part, 0x00040000 for a 256 KiB part), a zero word@8, and a word@12 that
#: is either an entry index (MG1) or a version pair (GE10 0x0003000d, GE8 0x0c).
#: Everything from +0x10 is the board's own MIPS code and data -- these PROMs run
#: on the graphics board's CPU, never on the host, so they are not a CPU PROM.
_PROM_11EE_MAGIC = 0x000011EE
_PROM_11EE_CODE_OFF = 0x20
#: Enough of an image to judge: a 64 KiB floor rules out a coincidental header on
#: a chip dump, and the recorded capacity must be able to hold what is present.
_PROM_11EE_MIN_SIZE = 0x10000
#: MIPS code-plausibility thresholds for a 256-word (1 KiB) window. Measured:
#: every held image scores 1.000 with >= 2 ``jr $ra`` and >= 4 J/JAL in the window,
#: while the same window over a pseudo-random tail (400 seeds per image) scores at
#: most 0.895, with **zero** ``jr $ra`` in all 1200 trials -- the return opcode
#: appears in real code and essentially never in random data, so it is the
#: discriminating claim.
_PROM_11EE_WINDOW = 256
_PROM_11EE_MIN_PLAUSIBLE = 0.99
_PROM_11EE_MIN_JR = 2
_PROM_11EE_MIN_JUMPS = 4


def _mips_plausible(word: int) -> bool:
    """True if *word* decodes as an instruction a compiler would emit.

    Opcodes outside the MIPS I-III set (reserved/immediate-full) are implausible;
    SPECIAL and REGIMM are checked against their real funct/rt fields, and the
    COP0/COP1/COP2 space only accepts the transfer and control sub-opcodes.
    """
    op = word >> 26
    if op not in _MIPS_OPS:
        return False
    if op == 0x00:
        return (word & 0x3F) in _MIPS_SPECIAL
    if op == 0x01:
        return ((word >> 16) & 0x1F) in _MIPS_REGIMM
    if op in (0x10, 0x11, 0x12):
        return ((word >> 21) & 0x1F) in (0, 1, 2, 3, 4, 0x10)
    return True


_MIPS_SPECIAL = frozenset(list(range(0x00, 0x10)) + [
    0x10, 0x11, 0x12, 0x18, 0x19, 0x1A, 0x1B, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x2A, 0x2B, 0x30, 0x31, 0x32, 0x33])
_MIPS_REGIMM = frozenset({0, 1, 2, 3, 16, 17, 18, 19, 20, 21, 22, 23})
_MIPS_OPS = frozenset([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x14, 0x15, 0x18, 0x19, 0x1A,
    0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x34, 0x35,
    0x36, 0x38, 0x39, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F])


def mips_code_window(data: bytes, start: int, words: int):
    """Measure a code window: ``(words, plausible, jr_ra, jumps)``.

    ``plausible`` counts words that decode as a compiler-emitted instruction,
    ``jr_ra`` counts the canonical subroutine return ``jr $ra`` (0x03e00008)
    and ``jumps`` counts J/JAL. Counted, not scored: a caller compares them.
    """
    end = min(len(data) - 3, start + 4 * words)
    total = plausible = jr_ra = jumps = 0
    for off in range(start, end, 4):
        word = int.from_bytes(data[off:off + 4], 'big')
        total += 1
        plausible += _mips_plausible(word)
        jr_ra += word == 0x03E00008
        jumps += (word >> 26) in (0x02, 0x03)
    return total, plausible, jr_ra, jumps


def _prom_11ee_header(data: bytes):
    """Decode a graphics-board PROM header, or None.

    Three independent claims: the ``0x000011ee`` magic, a recorded capacity that
    is a power of two able to hold the file, and the zero word at +8.
    """
    if len(data) < _PROM_11EE_MIN_SIZE:
        return None
    if int.from_bytes(data[0:4], 'big') != _PROM_11EE_MAGIC:
        return None
    capacity = int.from_bytes(data[4:8], 'big')
    if int.from_bytes(data[8:12], 'big') != 0:
        return None
    if capacity & (capacity - 1) or not len(data) <= capacity <= 0x1000000:
        return None
    return capacity, int.from_bytes(data[12:16], 'big')


def prom_11ee_entry_table(data: bytes):
    """The ``(j <target>, nop)`` table an MG1 PROM starts with, or [].

    Each 8-byte record is ``j`` (opcode 2) whose target is word-aligned, followed
    by a zero delay slot. The table starts at +0x10 and ends at the first record
    that is not one; the records are one branch table, so their targets share a
    64 KiB page.
    """
    off, targets = 0x10, []
    while off + 8 <= len(data):
        word = int.from_bytes(data[off:off + 4], 'big')
        delay = int.from_bytes(data[off + 4:off + 8], 'big')
        if (word >> 26) != 0x02 or delay != 0:
            break
        target = (word & 0x03FFFFFF) << 2
        if target & 3:
            break
        targets.append(target)
        off += 8
    if targets and len({t >> 16 for t in targets}) != 1:
        return []
    return targets


def is_prom_11ee_table(data: bytes) -> bool:
    """True for an MG1 graphics-board PROM: header + ``(j,nop)`` entry table.

    The claims, all from the image's own layout: the header (magic, capacity,
    zero word), a table of >= 2 ``(j,nop)`` records at +0x10 whose targets share
    one 64 KiB page, a NUL-terminated printable banner EXACTLY where the table
    ends (MG1's is ``CRIMSON startup prom Rev 0.00 12/25/91``), code from +0x80,
    and a code window that is plausible MIPS with real ``jr $ra`` returns.

    The banner is a corroborating string, not the evidence: an arm that fired on
    ``CRIMSON`` would be a filename-grade inference in printable form. What the
    arm tests is the record geometry and the code behind it -- a same-size body
    carrying the first 32 bytes and a random tail has no ``jr $ra`` at all.
    """
    if _prom_11ee_header(data) is None:
        return False
    targets = prom_11ee_entry_table(data)
    if len(targets) < 2:
        return False
    end = 0x10 + 8 * len(targets)
    nul = data.find(b'\x00', end)
    if nul < end + 8 or nul > 0x80:
        return False
    if not all(32 <= c < 127 or c in (9, 10, 13) for c in data[end:nul]):
        return False
    total, plausible, jr_ra, jumps = mips_code_window(
        data, 0x80, _PROM_11EE_WINDOW)
    return (total == _PROM_11EE_WINDOW
            and plausible / total >= _PROM_11EE_MIN_PLAUSIBLE
            and jr_ra >= _PROM_11EE_MIN_JR and jumps >= _PROM_11EE_MIN_JUMPS)


def is_prom_11ee_code(data: bytes) -> bool:
    """True for a GE8/GE10 graphics-board PROM: header + MIPS code at +0x20.

    The same header, but the words at +0x10 are entry addresses and a code
    extender rather than a branch table, and the board's code starts at +0x20.
    The evidence is the code: a 256-word window that is entirely plausible MIPS
    with >= 2 ``jr $ra`` and >= 4 J/JAL. An MG1 image is excluded explicitly
    (it has the table instead), so the two flavours never both fire; and a
    same-size body with the header and a random tail is refused, because random
    data produced 0 ``jr $ra`` in all 1200 measured trials.
    """
    if _prom_11ee_header(data) is None or prom_11ee_entry_table(data):
        return False
    total, plausible, jr_ra, jumps = mips_code_window(
        data, _PROM_11EE_CODE_OFF, _PROM_11EE_WINDOW)
    return (total == _PROM_11EE_WINDOW
            and plausible / total >= _PROM_11EE_MIN_PLAUSIBLE
            and jr_ra >= _PROM_11EE_MIN_JR and jumps >= _PROM_11EE_MIN_JUMPS)


#: ``ar`` archive magic, then a 60-byte member header per member. IRIX writes its
#: symbol table as the FIRST member, named ``__________EBEB_`` for a big-endian
#: archive (``EB`` = MIPSEB, ``EB`` = the "EB" hash/index flavour) and
#: ``__________EL``/other for the little-endian and 64-bit variants.
_AR_MAGIC = b'!<arch>\n'
_AR_HDR = 60
_AR_FMAG = b'`\n'
_AR_OCTAL = b'01234567'
#: The symbol-index body (`armap`): a count, that many 8-byte (name offset,
#: member offset) slots, a byte count, then the NUL-separated name block.
_AR_INDEX_SIZES = frozenset({32, 64})


def parse_ar_members(data: bytes):
    """Decode an ``ar`` archive's member headers, or None if they do not parse.

    Each header is ``name[16] date[12] uid[6] gid[6] mode[8] size[10] "`\\n"``:
    the name is space-padded, the numbers are space-padded ASCII (date/uid/gid/
    size decimal, mode octal). A member body follows immediately and is padded
    to an even offset. Returns ``[dict]`` with the decoded fields, or None when
    any header is malformed -- the layout is the evidence, so a body whose
    headers do not parse is not an archive.

    Truncation is reported rather than hidden: the six held archives are all cut
    inside their LAST member (``shmiq.o`` declares 14956 B and has 715), so
    ``truncated`` on the final member is expected and is the caller's decision.
    """
    n = len(data)
    if not data.startswith(_AR_MAGIC):
        return None
    off, members = len(_AR_MAGIC), []
    while off + _AR_HDR <= n:
        hdr = data[off:off + _AR_HDR]
        if hdr[58:60] != _AR_FMAG:
            return None
        name = hdr[0:16].rstrip(b' ').rstrip(b'/')
        date = hdr[16:28].rstrip(b' ')
        uid = hdr[28:34].rstrip(b' ')
        gid = hdr[34:40].rstrip(b' ')
        mode = hdr[40:48].rstrip(b' ')
        size = hdr[48:58].rstrip(b' ')
        if not name or not all(32 <= c < 127 for c in name):
            return None
        if not (date.isdigit() and uid.isdigit() and gid.isdigit()
                and size.isdigit()):
            return None
        if not mode or not all(c in _AR_OCTAL for c in mode):
            return None
        length = int(size)
        body = data[off + _AR_HDR:off + _AR_HDR + length]
        members.append({"offset": off, "name": name, "date": int(date),
                        "mode": mode, "size": length, "body": body,
                        "truncated": len(body) < length})
        off = off + _AR_HDR + length + (length & 1)
    return members or None


def ar_symbol_index(body: bytes):
    """Decode the ``__________EBEB_`` symbol index, or None if it is not one.

    Three claims, all the member's own: the slot count word is one of the two
    sizes IRIX writes (32 or 64), ``4 + 8*count + 4 + textlen`` is EXACTLY the
    member's length, and the pairs that follow name a real member -- each name
    offset lands on the start of a NUL-terminated printable name in the block at
    the end, and each member offset lands on a following member's header.

    Measured on the six held archives: 8-17 non-empty slots each, every member
    offset equal to the next member's real file offset, and the lengths closing
    exactly (e.g. 4 + 8*32 + 4 + 86 == 350).
    """
    n = len(body)
    if n < 24:
        return None
    slots = int.from_bytes(body[0:4], 'big')
    if slots not in _AR_INDEX_SIZES:
        return None
    names_at = 4 + 8 * slots
    if names_at + 4 > n:
        return None
    text_len = int.from_bytes(body[names_at:names_at + 4], 'big')
    if names_at + 4 + text_len != n:
        return None
    text = body[names_at + 4:]
    name_starts = {i for i in range(len(text)) if i == 0 or text[i - 1] == 0}
    if not all(c == 0 or 32 <= c < 127 for c in text):
        return None
    if not text or text[-1] != 0:
        return None
    entries = []
    for i in range(slots):
        name_off = int.from_bytes(body[4 + 8 * i:8 + 8 * i], 'big')
        member_off = int.from_bytes(body[8 + 8 * i:12 + 8 * i], 'big')
        if name_off == 0 and member_off == 0:
            continue
        if name_off not in name_starts or not member_off:
            return None
        end = text.find(b'\x00', name_off)
        entries.append((text[name_off:end], member_off))
    return entries or None


def is_mips_ar_archive(data: bytes) -> bool:
    """True for an IRIX MIPS ``ar`` archive of ECOFF objects.

    The evidence is the archive's own layout, in this order: the ``!<arch>\\n``
    magic, a first member named ``__________EBEB_`` (the big-endian MIPS symbol
    index) whose body parses as an index (:func:`ar_symbol_index`) and whose
    member offsets point at the real following headers, every non-final member
    complete (the held archives are cut inside their last), and the later
    members being MIPS ECOFF objects -- a ``0x0160``-family filehdr naming
    ``.text`` first. ``file(1)`` reads the same six as "MIPS archive with MIPSEB
    members and an EB hash table"; that is the outside oracle, not the evidence.

    A same-size body with the ``!<arch>`` line and the index member preserved and
    the rest random fails at the index's length arithmetic and at the ECOFF
    filehdr, so the arm is not satisfied by the first 60 bytes.
    """
    members = parse_ar_members(data)
    if members is None or len(members) < 2:
        return False
    if not members[0]["name"].startswith(b"__________E"):
        return False
    if not members[0]["name"].endswith(b"_"):
        return False
    entries = ar_symbol_index(members[0]["body"])
    if entries is None:
        return False
    offsets = {m["offset"] for m in members[1:]}
    if not all(off in offsets for _name, off in entries):
        return False
    if any(m["truncated"] for m in members[:-1]):
        return False
    last = members[-1]
    if len(last["body"]) < 0x4C:
        return False
    return any(_ecoff_filehdr_ok(m["body"]) for m in members[1:])


def _ecoff_filehdr_ok(body: bytes) -> bool:
    """True if *body* starts with a MIPS ECOFF filehdr that is self-consistent.

    Only the filehdr FIELDS are judged: the held archives are cut inside their
    last member, so a section table that reaches past the available bytes is the
    truncation, not a defect. The magic, the section count and the optional-header
    size are what the member declares about itself.
    """
    if len(body) < 20 or int.from_bytes(body[0:2], 'big') not in _ECOFF_MAGICS:
        return False
    nscns = int.from_bytes(body[2:4], 'big')
    opthdr = int.from_bytes(body[16:18], 'big')
    return 1 <= nscns <= 30 and opthdr in (0, 0x38)


def detect_prom_format(data: bytes) -> str:
    """Return the firmware format of *data* (one of the ``FORMAT_*`` constants).

    Magic checks (definitive) run first, most-specific first; the MIPS vector
    heuristic is only a fallback, so an SHDR container is never mistaken for a
    MIPS PROM whose first word merely decodes as a branch. The graphics-microcode
    arms run after the magics and before the vector fallback: each validates a
    structure the image declares about itself (record geometry, section table,
    reserved-bit mask), never a short prefix, and each is refused by the loader
    afterwards -- naming a microcode family is not a licence to disassemble it.
    """
    if len(data) < 16:
        return FORMAT_UNKNOWN

    # SN0/SN1 container magic at 0x40.
    if data[0x40:0x48] == b'JFKSWCSM':
        return FORMAT_SN_CONTAINER

    # O2/IP32 SHDR flash, before the vector heuristic: the first word
    # (0x10000011) decodes as a valid MIPS branch, and the SHDR headers are
    # themselves crafted branch instructions. Two on-disk forms:
    #   - raw flash dump: 'SHDR' at 0x08 (CPU reset vector hits it directly);
    #   - 'PROM' container: magic 'PROM'@0, flash data at 0x100.
    if data[0x08:0x0C] == SHDR_SEG_MAGIC:
        return FORMAT_SHDR
    if data[0:4] == PROM_CONTAINER_MAGIC and \
            data[PROM_CONTAINER_OFFSET + 8:PROM_CONTAINER_OFFSET + 12] == \
            SHDR_SEG_MAGIC:
        return FORMAT_SHDR

    for magic, fmt in _MAGIC_AT_ZERO:
        if data[:len(magic)] == magic:
            return fmt

    if len(data) >= 0x1C and data[0x18:0x1C] == b'\x5a\xa5\xa5\x5a':
        return FORMAT_MMSC_X86

    # Graphics-microcode families, from decoded structure. These run before the
    # MIPS-vector fallback because several are small enough to be mistaken for a
    # chip dump by that heuristic and none is a CPU PROM.
    if is_vfc_database(data):
        return FORMAT_VFC_DATABASE
    if is_ge11_microcode(data):
        return FORMAT_GE11_MICROCODE
    if is_vpro_microcode(data):
        return FORMAT_VPRO_MICROCODE
    if is_hq3_microcode(data):
        return FORMAT_HQ3_MICROCODE
    if is_ge7_microcode(data):
        return FORMAT_GE7_MICROCODE
    if is_ucode_object(data):
        return FORMAT_UCODE_OBJECT
    if is_gr2_microcode(data):
        return FORMAT_GR2_MICROCODE
    if is_mips_ecoff(data):
        return FORMAT_MIPS_ECOFF
    if is_ge_object(data):
        return FORMAT_GE_OBJECT
    if is_vof_timing(data):
        return FORMAT_VOF_TIMING
    if is_m68k_module(data):
        return FORMAT_M68K_MODULE
    if is_prom_11ee_table(data):
        return FORMAT_PROM_11EE_TABLE
    if is_prom_11ee_code(data):
        return FORMAT_PROM_11EE_CODE
    if is_mips_ar_archive(data):
        return FORMAT_MIPS_AR_ARCHIVE

    if is_spd_eeprom(data):
        return FORMAT_SPD_EEPROM

    if is_eeprom_vpd(data):
        return FORMAT_EEPROM_VPD

    if is_nvram_env(data):
        return FORMAT_NVRAM_ENV

    if is_text_image(data):
        return FORMAT_TEXT

    if is_mips_vector(data):
        return FORMAT_MIPS_VECTOR

    # Last resort: a raw flash dump stored 16-bit word-swapped (e.g. the IP35/
    # Fuel AM29LV160 motherboard PROM). Strong evidence only (>=8 KiB + a
    # decoded jump-table run), so I2C/EEPROM chip dumps stay refused.
    if is_swapped_mips_vector(data):
        return FORMAT_MIPS_VECTOR_SWAPPED

    return FORMAT_UNKNOWN


def describe_prom_format(fmt: str) -> str:
    """Human-readable name for a detected format."""
    return _DESCRIPTIONS.get(fmt, fmt)


def jfk4_load_address(data: bytes) -> int:
    """Load address of an IO4 'JFK4' image (field at 0x08)."""
    return int.from_bytes(data[0x08:0x0C], 'big') if len(data) >= 0x10 else 0


def jfk4_code_size(data: bytes) -> int:
    """Code size of an IO4 'JFK4' image (field at 0x0c); 0 if unreadable."""
    return int.from_bytes(data[0x0C:0x10], 'big') if len(data) >= 0x10 else 0


@dataclass
class JKSWSegment:
    """One `promseg_t` from an IO4 'JKSW' image (sys/EVEREST/promhdr.h)."""
    type: int
    offset: int
    entry: int
    start_address: int
    length: int
    checksum: int

    @property
    def is_master(self) -> bool:
        return (self.type & JKSW_STYPE_MASK) == JKSW_STYPE_MASTER


def parse_jksw(data: bytes) -> Optional[List[JKSWSegment]]:
    """Parse the IO4 'JKSW' segment table, or None if the table is absent.

    Layout from ``sys/EVEREST/promhdr.h``: the `evpromhdr_t` at 0x00 is
    followed by the `seginfo_t` at **0x18** (measured; the header's
    ``SEGINFO_OFFSET`` of 0x100 is absent in every library image). Every field
    is bounds-checked; a table whose ``si_magic`` is wrong or whose ``numsegs``
    is out of 1..16 is rejected rather than guessed at.
    """
    if data[0:4] != b'JKSW':
        return None
    base = JKSW_SEGINFO_OFFSET
    if base + 8 > len(data):
        return None
    si_magic = int.from_bytes(data[base:base + 4], 'big')
    numsegs = int.from_bytes(data[base + 4:base + 8], 'big')
    if si_magic != JKSW_SI_MAGIC or not (1 <= numsegs <= JKSW_MAXSEGS):
        return None
    segs: List[JKSWSegment] = []
    p = base + 8
    for _ in range(numsegs):
        if p + JKSW_SEG_SIZE > len(data):
            return None
        segs.append(JKSWSegment(
            type=int.from_bytes(data[p:p + 4], 'big'),
            offset=int.from_bytes(data[p + 4:p + 8], 'big'),
            entry=int.from_bytes(data[p + 8:p + 16], 'big'),
            start_address=int.from_bytes(data[p + 16:p + 24], 'big'),
            length=int.from_bytes(data[p + 24:p + 28], 'big'),
            checksum=int.from_bytes(data[p + 28:p + 32], 'big'),
        ))
        p += JKSW_SEG_SIZE
    return segs


def jksw_entry_segment(segs: List[JKSWSegment]) -> Optional[JKSWSegment]:
    """The segment carrying the entry code: the MASTER segment, else the first."""
    for s in segs:
        if s.is_master:
            return s
    return segs[0] if segs else None


def shdr_flash_offset(data: bytes) -> int:
    """File offset where an O2/IP32 SHDR flash image begins.

    0x100 for the ``'PROM'`` container form, 0 for a raw flash dump. The CPU
    reset vector (0xBFC00000) maps to this offset.
    """
    if data[0:4] == PROM_CONTAINER_MAGIC:
        return PROM_CONTAINER_OFFSET
    return 0


def _shdr_word_sum_zero(flash: bytes, start: int, end: int) -> bool:
    """True iff the big-endian 32-bit word sum over ``[start, end)`` is zero.

    ``end`` is exclusive. Both ranges are checked against ``len(flash)`` so a
    truncated segment reports False rather than reading past EOF.
    """
    if start < 0 or end > len(flash) or start >= end:
        return False
    total = 0
    for off in range(start, end, 4):
        total = (total + int.from_bytes(flash[off:off + 4], 'big')) & 0xFFFFFFFF
    return total == 0


@dataclass
class SHDRSegment:
    """One segment from an O2/IP32 (SHDR) flash image.

    Every field is read from the image; ``header_sum_ok`` / ``body_sum_ok`` are
    the PROM's own self-zeroing checksum verdicts (the same two QEMU validates
    in ``sgi_o2_validate_prom_checksums``), so a corrupt segment is named rather
    than silently sliced. ``label`` is ``name`` or a ``<#n>`` fallback.
    """
    offset: int          # flash offset of the 64-byte header
    length: int          # segLen (header + body)
    name: str
    version: str
    name_len: int
    vsn_len: int
    seg_type: int        # 1=code, 3=code w/ subsection table, 0/other=data
    aux: int
    first_word: int      # word at +0x00 (the crafted reset branch for code segs)
    checksum: int        # stored header checksum at +0x3c
    header_sum_ok: bool
    body_sum_ok: bool

    @property
    def label(self) -> str:
        return self.name or "<#0x{:x}>".format(self.offset)


def parse_shdr_segments(flash: bytes) -> List[SHDRSegment]:
    """Parse the SHDR segment table of an O2/IP32 flash image.

    Segments sit on 256-byte page boundaries; each is a 64-byte header with
    ``'SHDR'`` at +8 and ``segLen`` at +0xc, followed by its body. The walk
    mirrors ``hw/mips/sgi_o2.c``; a segment whose ``segLen`` is malformed is
    skipped (one page forward) rather than trusted, so a corrupt table yields a
    short list instead of a bogus slice.
    """
    segs: List[SHDRSegment] = []
    off = 0
    while off + SHDR_SEG_HDR <= len(flash):
        if flash[off + 8:off + 12] != SHDR_SEG_MAGIC:
            off += SHDR_SEG_PAGE
            continue
        seg_len = int.from_bytes(flash[off + SHDR_SEG_LEN_OFF:off + SHDR_SEG_LEN_OFF + 4], 'big')
        name = flash[off + SHDR_SEG_NAME_OFF:off + SHDR_SEG_NAME_OFF + SHDR_SEG_NAME_LEN]
        name = name.split(b'\x00', 1)[0].decode('latin-1')
        vsn = flash[off + SHDR_SEG_VSN_OFF:off + SHDR_SEG_VSN_OFF + SHDR_SEG_VSN_LEN]
        vsn = vsn.split(b'\x00', 1)[0].decode('latin-1')
        # Header checksum covers words [off, off+0x3c) plus the checksum word.
        header_sum_ok = _shdr_word_sum_zero(flash, off, off + SHDR_SEG_HDRSUM_OFF + 4)
        body_sum_ok = False
        if SHDR_SEG_HDR <= seg_len <= len(flash) - off:
            body_end = off + seg_len
            last_off = ((body_end + 3) & ~3) - 4
            if last_off >= off + SHDR_SEG_BODY_OFF + 4:
                body_sum_ok = _shdr_word_sum_zero(flash, off + SHDR_SEG_BODY_OFF,
                                                  last_off + 4)
        segs.append(SHDRSegment(
            offset=off,
            length=seg_len,
            name=name,
            version=vsn,
            name_len=flash[off + SHDR_SEG_FIELD_OFF],
            vsn_len=flash[off + SHDR_SEG_FIELD_OFF + 1],
            seg_type=flash[off + SHDR_SEG_FIELD_OFF + 2],
            aux=flash[off + SHDR_SEG_FIELD_OFF + 3],
            first_word=int.from_bytes(flash[off:off + 4], 'big'),
            checksum=int.from_bytes(
                flash[off + SHDR_SEG_HDRSUM_OFF:off + SHDR_SEG_HDRSUM_OFF + 4], 'big'),
            header_sum_ok=header_sum_ok,
            body_sum_ok=body_sum_ok,
        ))
        if seg_len < SHDR_SEG_HDR or seg_len > len(flash) - off:
            off += SHDR_SEG_PAGE
        else:
            off += (seg_len + SHDR_SEG_PAGE - 1) & ~(SHDR_SEG_PAGE - 1)
    return segs


def shdr_segment_count(flash: bytes) -> int:
    """Count SHDR segments in an O2/IP32 flash image.

    Segments sit on 256-byte page boundaries; each has ``'SHDR'`` at +8 and a
    ``segLen`` at +0xc. Mirrors the walk in hw/mips/sgi_o2.c. Used only for a
    human-readable mapping note.
    """
    return len(parse_shdr_segments(flash))
