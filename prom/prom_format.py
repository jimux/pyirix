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

from typing import Optional

# --- recognised formats -----------------------------------------------------
FORMAT_SN_CONTAINER = "sn-container"   # JFKSWCSM @0x40 (IP27/IP35/IO6)
FORMAT_SHDR = "shdr"                   # "SHDR" @0x08 (IP32/O2, and its flash)
FORMAT_MIPS_ELF = "mips-elf"           # \x7fELF @0 (Venice graphics)
FORMAT_SYSCO_68K = "68k-sysco"         # "ESTFBINR" @0 (Origin L1/L2)
FORMAT_X86_BIOS = "x86-bios"           # \x55\xaa @0 (Voyager/ATI)
FORMAT_KONA_ARM = "kona-arm"           # 0xbadc0ffe @0 (InfiniteReality)
FORMAT_MMSC_X86 = "mmsc-x86"           # 0x5aa5a55a @0x18 (MMSC)
FORMAT_GE_MICROCODE = "ge-microcode"   # "EA\x00\x01" @0 (GE5/GE7)
FORMAT_IO4_CONTAINER = "io4-container"  # "JKSW"/"JFK4" @0
FORMAT_MIPS_VECTOR = "mips-vector"     # classic SGI CPU PROM (IP4..IP30)
FORMAT_UNKNOWN = "unknown"

#: Formats that are positively NOT a raw MIPS PROM image. A disassembler must
#: refuse these (annotate) rather than present fabricated MIPS. ``sn-container``,
#: ``shdr`` and ``mips-vector`` ARE MIPS images (SHDR/O2 flash is flat-executable
#: at 0xBFC00000); an unknown is left to the caller's old behaviour rather than
#: refused on a guess.
NON_MIPS_FORMATS = frozenset({
    FORMAT_MIPS_ELF,
    FORMAT_SYSCO_68K,
    FORMAT_X86_BIOS,
    FORMAT_KONA_ARM,
    FORMAT_MMSC_X86,
    FORMAT_GE_MICROCODE,
    FORMAT_IO4_CONTAINER,
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

_MAGIC_AT_ZERO = (
    (b'\x7fELF', FORMAT_MIPS_ELF),
    (b'ESTFBINR', FORMAT_SYSCO_68K),
    (b'\x55\xaa', FORMAT_X86_BIOS),
    (b'\xba\xdc\x0f\xfe', FORMAT_KONA_ARM),
    (b'JKSW', FORMAT_IO4_CONTAINER),
    (b'JFK4', FORMAT_IO4_CONTAINER),
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
    FORMAT_IO4_CONTAINER: "IO4 firmware container (JKSW/JFK4)",
    FORMAT_MIPS_VECTOR: "classic SGI MIPS CPU PROM",
    FORMAT_UNKNOWN: "unrecognised firmware",
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

    if is_mips_vector(data):
        return FORMAT_MIPS_VECTOR

    return FORMAT_UNKNOWN


def describe_prom_format(fmt: str) -> str:
    """Human-readable name for a detected format."""
    return _DESCRIPTIONS.get(fmt, fmt)


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

