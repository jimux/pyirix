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
FORMAT_IO4_JFK4 = "io4-jfk4"           # "JFK4"@0: flat MIPS w/ 0x18 header
FORMAT_IO4_JKSW = "io4-jksw"           # "JKSW"@0: Everest segment table
FORMAT_MIPS_VECTOR = "mips-vector"     # classic SGI CPU PROM (IP4..IP30)
FORMAT_TEXT = "text-data"              # plain text / data (not firmware)
FORMAT_UNKNOWN = "unknown"

#: Formats that are positively NOT a raw MIPS PROM image, and so must be
#: REFUSED (annotated) rather than disassembled -- presenting flat MIPS for any
#: of these fabricates output. ``sn-container``, ``shdr``, ``io4-jfk4``,
#: ``io4-jksw`` and ``mips-vector`` are images we CAN slice. ``unknown`` is
#: included: an image that fails every positive check cannot be vouched for, so
#: it is refused with a named reason rather than guessed at (the 49 library
#: files that land here are I2C/EEPROM chip dumps, graphics microcode,
#: controller/EPROM/flash images and two plain-text files -- none a CPU PROM).
NON_MIPS_FORMATS = frozenset({
    FORMAT_MIPS_ELF,
    FORMAT_SYSCO_68K,
    FORMAT_X86_BIOS,
    FORMAT_KONA_ARM,
    FORMAT_MMSC_X86,
    FORMAT_GE_MICROCODE,
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
    FORMAT_IO4_JFK4: "IO4 'JFK4' MIPS image (load 0x81800000, code@0x18)",
    FORMAT_IO4_JKSW: JKSW_DESCRIPTION,
    FORMAT_MIPS_VECTOR: "classic SGI MIPS CPU PROM",
    FORMAT_TEXT: "plain text / data (not firmware)",
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
    if len(data) < 8:
        return False
    valid = {0x02, 0x04, 0x10, 0x01}   # J, BEQ, COP0, REGIMM
    if (_word(data, 0) >> 26) & 0x3F in valid:
        return True
    if _word(data, 0) == 0 and ((_word(data, 4) >> 26) & 0x3F) in valid:
        return True
    return False


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

    if is_text_image(data):
        return FORMAT_TEXT

    if is_mips_vector(data):
        return FORMAT_MIPS_VECTOR

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

