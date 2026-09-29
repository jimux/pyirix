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
FORMAT_GE_MICROCODE = "ge-microcode"   # "EA\x00\x01" @0 (GE5/GE7)
FORMAT_GE7_MICROCODE = "ge7-microcode" # 96 6e 00 01 ... @0 (GE7 header)
FORMAT_HQ3_MICROCODE = "hq3-microcode" # 00 83 82 @0 (Impact HQ3/MGRAS)
FORMAT_GR2_MICROCODE = "gr2-microcode" # 01 60 00 05 2b 91 @0 (GR2 ucode)
FORMAT_VPRO_MICROCODE = "vpro-microcode"  # 04 a4 00 00 01 20 c0 00 @0 (Buzz)
FORMAT_GE11_MICROCODE = "ge11-microcode"  # 12-byte ge_ucode records (GE11/Impact)
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
# SHDR flash segment header: magic 'SHDR' at +0x08, segLen at +0x0c,
# 64-byte header, segments page-aligned at 256-byte intervals.
SHDR_SEG_MAGIC = b'SHDR'
SHDR_SEG_PAGE = 256
SHDR_SEG_HDR = 0x40

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
    # Content magics established from the PROM_library corpus (NOT from
    # filenames -- a name is not evidence). Each is a real shared byte header
    # observed across the family's images. GE7: 4 images share the exact 16-byte
    # header; HQ3: 2 share the 3-byte prefix; GR2: 2 share 6 bytes; VPro Buzz: 1
    # image (weakest evidence, kept because the header is self-consistent).
    (b'\x96\x6e\x00\x01', FORMAT_GE7_MICROCODE),
    (b'\x00\x83\x82', FORMAT_HQ3_MICROCODE),
    (b'\x01\x60\x00\x05\x2b\x91', FORMAT_GR2_MICROCODE),
    (b'\x04\xa4\x00\x00\x01\x20\xc0\x00', FORMAT_VPRO_MICROCODE),
)

_DESCRIPTIONS = {
    FORMAT_SN_CONTAINER: "SN0/SN1 container (JFKSWCSM@0x40; IP27/IP35/IO6)",
    FORMAT_SHDR: "O2/IP32 SHDR container ('SHDR'@0x08)",
    FORMAT_MIPS_ELF: "MIPS ELF image",
    FORMAT_SYSCO_68K: "68K system controller firmware (ESTFBINR)",
    FORMAT_X86_BIOS: "x86 firmware / VGA BIOS (55AA)",
    FORMAT_KONA_ARM: "ARM transport processor firmware (KONA)",
    FORMAT_MMSC_X86: "MMSC controller firmware (x86, 5aa5a55a@0x18)",
    FORMAT_GE_MICROCODE: "GE5/GE7 graphics microcode",
    FORMAT_GE7_MICROCODE: "GE7 graphics microcode (96 6e 00 01 header)",
    FORMAT_HQ3_MICROCODE: "Impact HQ3/MGRAS graphics microcode",
    FORMAT_GR2_MICROCODE: "GR2 graphics microcode",
    FORMAT_VPRO_MICROCODE: "VPro Buzz transform-engine microcode",
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
    if (_word(data, 0) >> 26) & 0x3F in valid:
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


def detect_prom_format(data: bytes) -> str:
    """Return the firmware format of *data* (one of the ``FORMAT_*`` constants).

    Magic checks (definitive) run first, most-specific first; the MIPS vector
    heuristic is only a fallback, so an SHDR container is never mistaken for a
    MIPS PROM whose first word merely decodes as a branch.
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

    if is_ge11_microcode(data):
        return FORMAT_GE11_MICROCODE

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


def shdr_segment_count(flash: bytes) -> int:
    """Count SHDR segments in an O2/IP32 flash image.

    Segments sit on 256-byte page boundaries; each has ``'SHDR'`` at +8 and a
    ``segLen`` at +0xc. Mirrors the walk in hw/mips/sgi_o2.c. Used only for a
    human-readable mapping note.
    """
    n = 0
    off = 0
    while off + SHDR_SEG_HDR <= len(flash):
        if flash[off + 8:off + 12] != SHDR_SEG_MAGIC:
            off += SHDR_SEG_PAGE
            continue
        seg_len = int.from_bytes(flash[off + 12:off + 16], 'big')
        n += 1
        if seg_len < SHDR_SEG_HDR or seg_len > len(flash) - off:
            off += SHDR_SEG_PAGE
        else:
            off += (seg_len + SHDR_SEG_PAGE - 1) & ~(SHDR_SEG_PAGE - 1)
    return n

