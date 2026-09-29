# SGI PROM Comparative Analysis - PROM Loader
"""
PROM loading with caching, platform detection, and metadata extraction.
"""

import gzip
import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from functools import lru_cache

from .config import (
    PROM_DIR, PROM_LIBRARY_DIR, PROM_BASE, ENTRY_POINT_OFFSET,
    detect_platform, PLATFORMS, prom_offset_to_addr
)
from .prom_format import (
    NON_MIPS_FORMATS, FORMAT_SN_CONTAINER, FORMAT_SHDR, FORMAT_IO4_JFK4,
    FORMAT_IO4_JKSW, FORMAT_MIPS_VECTOR, FORMAT_MIPS_VECTOR_SWAPPED,
    JFK4_CODE_OFFSET,
    detect_prom_format, describe_prom_format,
    shdr_flash_offset, SHDRSegment, parse_shdr_segments, SHDR_SEG_BODY_OFF,
    jfk4_load_address, jfk4_code_size,
    parse_jksw, jksw_entry_segment, swap_words16,
)
from .prom_compress import (
    DecompressError, lzw_decompress, rle_decompress,
)


def jksw_lzw_segments(data: bytes) -> List[bytes]:
    """Decode the LZW blocks stored in an IO4 ``JKSW`` flash image.

    The blocks are self-describing (``prom_lzw_hdr_t`` + compress(1) stream) and
    packed back-to-back; each runs to the next block's magic or EOF (measured on
    the three ``io4prom*`` images, whose declared lengths and checksums all
    verify). Returns the decoded segments in file order.
    """
    out: List[bytes] = []
    magic = b"_LZW"
    offs: List[int] = []
    i = data.find(magic)
    while i != -1:
        offs.append(i)
        i = data.find(magic, i + 1)
    for k, off in enumerate(offs):
        end = offs[k + 1] if k + 1 < len(offs) else len(data)
        out.append(lzw_decompress(data[off:end]))
    return out


@dataclass
class PromMetadata:
    """Metadata for a PROM file."""
    filename: str
    filepath: Path
    size: int
    sha256: str
    platform: Optional[str]
    endian: str  # "big" or "little" (byte-swapped)
    entry_point: int  # Entry point address from header
    part_number: Optional[str]  # SGI part number if detectable
    vectors: Dict[str, int] = field(default_factory=dict)
    # SN0/SN1 container mapping (None/False for a plain PROM).
    is_container: bool = False
    code_offset: int = 0          # file offset of the MIPS code slice
    code_size: int = 0            # length of the MIPS code slice
    load_address: int = 0         # 64-bit SN load address (raw)
    code_base: int = 0            # 32-bit PROM-segment address of code[0]
    mapping_note: str = ""        # human-readable "which mapping" line


# ---------------------------------------------------------------------------
# SN0/SN1 container support (Origin 2000/IP27, Origin 3000/IP35, IO6).
#
# SN-family PROMs use the `promhdr_t` format defined in
# `sys/SN/promhdr.h` (IRIX SDK): a fixed header (magic PROM_MAGIC
# "JFKSWCSM" at 0x40, length at 0x50, numsegs at 0x78) followed by up to
# PROM_MAXSEGS=16 `promseg_t` descriptors starting at 0x80. Each descriptor is
# 128 bytes: name[16], flags, offset, entry, loadaddr, length, length_c, sum,
# sum_c, memlength, resv1[5]. The first (and here only) segment's MIPS image is
# at `offset` (PROM_DATA_OFFSET = 0x1000) and is loaded at `loadaddr`.
#
# There is NO fixup/relocation table in this container: `sum`/`sum_c` are byte
# checksums, and `sgi_ip27_load_prom` copies the (uncompressed) segment raw.
# Disassembling the file from offset 0 decodes the header as NOPs; the code
# below slices the segment out and reports the address it must be at.
#
# The QEMU loader's shorthand "load_addr at 0xA0" is the descriptor's `entry`;
# the true `loadaddr` is at 0xA8. They are equal for IP27/IP35 but differ for
# IO6 (entry = loadaddr + 0x140), so the base is taken from 0xA8.
# ---------------------------------------------------------------------------
SN0_MAGIC = b'JFKSWCSM'
SN0_MAGIC_OFFSET = 0x40
SN0_REVISION_ADDR = 0x38
SN0_VERSION_ADDR = 0x48
SN0_TOTAL_SIZE_ADDR = 0x50
SN0_NUMSEGS_ADDR = 0x78
SN0_SEGS_OFFSET = 0x80
SN0_MAXSEGS = 16                              # PROM_MAXSEGS in sys/SN/promhdr.h
SN0_SEG_DESC_SIZE = 0x80                       # sizeof(promseg_t)
# First promseg_t descriptor (offsets absolute in the file).
SN0_MODULE_NAME_ADDR = SN0_SEGS_OFFSET        # name[16]
SN0_SEG_FLAGS_ADDR = 0x90
SN0_CODE_OFFSET_ADDR = 0x98                   # segment offset
SN0_ENTRY_ADDR = 0xA0                         # segment entry point
SN0_LOAD_ADDR_ADDR = 0xA8                     # segment loadaddr
SN0_CODE_SIZE_ADDR = 0xB0                     # segment true length
SN0_CODE_SIZE_C_ADDR = 0xB8                   # segment compressed length
SN0_SUM_ADDR = 0xC0                           # segment true byte sum (checksum)
SN0_SUM_C_ADDR = 0xC8                         # compressed byte sum
SN0_MEMLENGTH_ADDR = 0xD0                     # true length + BSS length
PROM_DATA_OFFSET = 0x1000

# promseg_t.flags compression field (SFLAG_* in sys/SN/promhdr.h).
SN0_SFLAG_COMPMASK = 0x7
SN0_SFLAG_NONE = 0
SN0_SFLAG_RLE = 1
SN0_SFLAG_LZW = 2
SN0_SFLAG_GZIP = 3
SN0_SFLAG_LOADABLE = 0x10

# Low physical region where SGI PROM segments are mapped; KSEG1 is +0xa0000000.
PROM_PHYS_BASE = 0x1fc00000   # classic CPU PROM physical base
PROM_PHYS_END = 0x20000000


@dataclass
class SN0Segment:
    """One `promseg_t` descriptor from an SN0/SN1 container."""
    name: str
    flags: int
    offset: int
    entry: int
    load_address: int
    length: int
    length_c: int


@dataclass
class SN0ContainerInfo:
    """Parsed SN0/SN1 (`promhdr_t`) container header (first segment)."""
    module_name: str
    revision: int
    version: int
    total_size: int
    numsegs: int
    flags: int
    code_offset: int
    entry: int
    load_address: int
    code_size: int
    code_size_c: int
    sum: int
    sum_c: int
    memlength: int
    segments: List[SN0Segment] = field(default_factory=list)


@dataclass
class PromCodeImage:
    """A PROM's MIPS code slice plus the address it is mapped at.

    Plain PROMs: ``data`` is the whole image and ``load_address`` is PROM_BASE.
    SN containers: ``data`` is the code slice and ``load_address`` is its
    translated (KSEG1) base, ready to hand to a disassembler.
    """
    data: bytes
    load_address: int
    file_offset: int
    code_size: int
    is_container: bool = False
    container: Optional[SN0ContainerInfo] = None
    mapping_note: str = ""
    format: str = FORMAT_MIPS_VECTOR   # see pyirix.prom.prom_format
    # For an O2/IP32 SHDR flash image, the parsed segment table. The single
    # ``load_address`` is the CPU reset base (segment 0 / sloader) only; later
    # segments execute elsewhere (firmware at 0x81000000). See shdr_segment_vma.
    shdr_segments: Optional[List[SHDRSegment]] = None

    def reset_entry(self, endian: str = "big") -> int:
        """The CPU reset entry for this code slice (the J target at its start).

        Distinct from the SN-container header's ``entry`` field, which is the
        raw load/entry value (e.g. ``0xc00000001fc00000`` for IP35) -- NOT the
        address the CPU starts executing at. For IP35 this returns ``0xbfc00400``
        (the charter's entry); for IP27 ``0xbfc00800``. Apply it to the SLICE
        (``self.data``), which is what this image is.
        """
        return extract_entry_point(self.data, endian)


# Cache for loaded PROM data
_prom_cache: Dict[str, bytes] = {}
_metadata_cache: Dict[str, PromMetadata] = {}


_PROM_EXTS = (".bin", ".img", ".rom", ".image")


def list_prom_files() -> List[Path]:
    """List PROM images under PROM_library (all supported extensions)."""
    if not PROM_LIBRARY_DIR.is_dir():
        return []
    proms = [p for p in PROM_LIBRARY_DIR.rglob("*")
             if p.is_file() and p.suffix.lower() in _PROM_EXTS]
    return sorted(proms, key=lambda p: str(p).lower())


def get_prom_path(filename: str) -> Optional[Path]:
    """Resolve a PROM by absolute path, or by name/path under PROM_library.

    Accepts: an absolute path; a workspace-relative path INCLUDING the
    'PROM_library/' prefix; a path relative to PROM_library ('bins/cpu/...') or
    to the library's 'bins/' ('cpu/ip35/...'); a bare file name found in the
    per-platform directories under PROM_library/bins/cpu/<platform>/; or a bare
    file name found anywhere under PROM_library. Resolution is against the
    WORKSPACE root, not the repo root — the fix for names that used to resolve
    to nothing when the code lives in a sub-repo.
    """
    fp = Path(filename)
    if fp.is_absolute():
        return fp if fp.exists() else None
    for cand in (PROM_DIR / filename, PROM_LIBRARY_DIR / filename):
        if cand.exists():
            return cand
    # Library layout: PROM_library/bins/cpu/<platform>/<file>. Try the path
    # relative to bins/, and the platform dirs by name, before the generic
    # recursive fallback (so a platform-prefixed name is unambiguous and fast).
    bins = PROM_LIBRARY_DIR / "bins"
    cpu = bins / "cpu"
    for cand in (bins / filename, cpu / filename):
        if cand.exists():
            return cand
    for plat in PLATFORMS:
        cand = cpu / plat / filename
        if cand.exists():
            return cand
    if cpu.is_dir():
        for d in sorted(cpu.iterdir()):
            if d.is_dir() and (d / filename).exists():
                return d / filename
    name = fp.name.lower()
    if PROM_LIBRARY_DIR.is_dir():
        for p in PROM_LIBRARY_DIR.rglob("*"):
            if p.is_file() and p.name.lower() == name:
                return p
    return None


def load_prom(filename: str, use_cache: bool = True) -> Optional[bytes]:
    """
    Load PROM binary data.

    Args:
        filename: PROM filename
        use_cache: Whether to use cached data

    Returns:
        Raw PROM bytes or None if not found
    """
    if use_cache and filename in _prom_cache:
        return _prom_cache[filename]

    path = get_prom_path(filename)
    if not path:
        return None

    data = path.read_bytes()

    if use_cache:
        _prom_cache[filename] = data

    return data


def detect_endianness(data: bytes) -> str:
    """
    Detect if PROM is big-endian (native) or byte-swapped.

    SGI PROMs are natively big-endian. Some dumps may be byte-swapped
    due to EPROM programmer quirks.
    """
    if len(data) < 4:
        return "big"

    # Check for common MIPS instruction patterns at offset 0
    # Big-endian MIPS instructions have opcode in high bits
    word = struct.unpack(">I", data[0:4])[0]
    opcode = (word >> 26) & 0x3f

    # Common PROM start opcodes (big-endian):
    # 0x00 = SPECIAL (including NOP)
    # 0x04 = BEQ
    # 0x05 = BNE
    # 0x08 = ADDI
    # 0x0f = LUI
    # 0x10 = COP0
    valid_big_opcodes = {0x00, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

    if opcode in valid_big_opcodes:
        return "big"

    # Try byte-swapped interpretation
    word_swap = struct.unpack("<I", data[0:4])[0]
    opcode_swap = (word_swap >> 26) & 0x3f

    if opcode_swap in valid_big_opcodes:
        return "little"

    # Default to big-endian
    return "big"


def extract_part_number(filename: str) -> Optional[str]:
    """
    Extract SGI part number from filename.

    Examples:
        "Indy_ip24prom.070-9101-007.bin" -> "070-9101-007"
        "Indigo_2_ip22prom.070-8127-002.bin" -> "070-8127-002"
    """
    import re
    match = re.search(r'(\d{3}-\d{4}-\d{3})', filename)
    if match:
        return match.group(1)
    return None


def read_u32_be(data: bytes, offset: int) -> int:
    """Read big-endian 32-bit unsigned integer."""
    if offset + 4 > len(data):
        return 0
    return struct.unpack(">I", data[offset:offset + 4])[0]


def read_u32_le(data: bytes, offset: int) -> int:
    """Read little-endian 32-bit unsigned integer."""
    if offset + 4 > len(data):
        return 0
    return struct.unpack("<I", data[offset:offset + 4])[0]


def read_u64_be(data: bytes, offset: int) -> int:
    """Read big-endian 64-bit unsigned integer (0 if out of range)."""
    if offset + 8 > len(data):
        return 0
    return struct.unpack(">Q", data[offset:offset + 8])[0]


def is_sn0_container(data: bytes) -> bool:
    """Return True if *data* carries the SN0/SN1 "JFKSWCSM" container magic."""
    end = SN0_MAGIC_OFFSET + len(SN0_MAGIC)
    if len(data) < end:
        return False
    return data[SN0_MAGIC_OFFSET:end] == SN0_MAGIC


def _parse_segment(data: bytes, base: int) -> SN0Segment:
    """Parse one 0x80-byte ``promseg_t`` descriptor at absolute *base*."""
    name_raw = data[base:base + 16]
    name = name_raw.split(b'\x00', 1)[0].decode('ascii', errors='replace')
    return SN0Segment(
        name=name,
        flags=read_u64_be(data, base + 0x10),
        offset=read_u64_be(data, base + 0x18),
        entry=read_u64_be(data, base + 0x20),
        load_address=read_u64_be(data, base + 0x28),
        length=read_u64_be(data, base + 0x30),
        length_c=read_u64_be(data, base + 0x38),
    )


def parse_sn0_container(data: bytes) -> Optional[SN0ContainerInfo]:
    """Parse an SN0/SN1 container header exactly as the IP27 QEMU loader reads it.

    Returns None when the magic is absent. The returned fields may be invalid
    (e.g. a zero code_size on a truncated dump); validation happens in
    :func:`extract_prom_code`.
    """
    if not is_sn0_container(data):
        return None

    name_raw = data[SN0_MODULE_NAME_ADDR:SN0_MODULE_NAME_ADDR + 16]
    module_name = name_raw.split(b'\x00', 1)[0].decode('ascii', errors='replace')

    numsegs = read_u64_be(data, SN0_NUMSEGS_ADDR)
    segments: List[SN0Segment] = []
    if 1 <= numsegs <= SN0_MAXSEGS:
        for i in range(numsegs):
            base = SN0_SEGS_OFFSET + i * SN0_SEG_DESC_SIZE
            if base + SN0_SEG_DESC_SIZE > len(data):
                break
            segments.append(_parse_segment(data, base))

    return SN0ContainerInfo(
        module_name=module_name,
        revision=read_u64_be(data, SN0_REVISION_ADDR),
        version=read_u64_be(data, SN0_VERSION_ADDR),
        total_size=read_u64_be(data, SN0_TOTAL_SIZE_ADDR),
        numsegs=numsegs,
        flags=read_u64_be(data, SN0_SEG_FLAGS_ADDR),
        code_offset=read_u64_be(data, SN0_CODE_OFFSET_ADDR),
        entry=read_u64_be(data, SN0_ENTRY_ADDR),
        load_address=read_u64_be(data, SN0_LOAD_ADDR_ADDR),
        code_size=read_u64_be(data, SN0_CODE_SIZE_ADDR),
        code_size_c=read_u64_be(data, SN0_CODE_SIZE_C_ADDR),
        sum=read_u64_be(data, SN0_SUM_ADDR),
        sum_c=read_u64_be(data, SN0_SUM_C_ADDR),
        memlength=read_u64_be(data, SN0_MEMLENGTH_ADDR),
        segments=segments,
    )


def _prom_phys_of(load_address: int) -> Optional[int]:
    """Reduce a load address (XKPHYS / KSEG0 / KSEG1 / physical) to PROM phys.

    Returns None when the address does not land in the low physical region where
    SGI PROM segments are mapped (classic CPU PROM 0x1fc00000, SN IO6 PROM
    0x11c00000, ...).
    """
    if load_address >= (1 << 32):
        # XKPHYS: physical address is the low 59-bit field (e.g.
        # 0xc0000000_1fc00000 -> 0x1fc00000).
        phys = load_address & 0x07ffffffffffffff
    elif 0xa0000000 <= load_address < 0xc0000000:
        phys = load_address - 0xa0000000  # KSEG1
    elif 0x80000000 <= load_address < 0xa0000000:
        phys = load_address - 0x80000000  # KSEG0
    else:
        phys = load_address
    if 0 < phys < PROM_PHYS_END:
        return phys
    return None


def prom_code_base(load_address: int) -> int:
    """Map a container load address to the 32-bit KSEG1 PROM segment.

    The disassembler speaks KSEG1 (0xbfc00000), while SN containers declare a
    64-bit XKPHYS load address (e.g. 0xc0000000_1fc00000). Falls back to
    ``PROM_BASE`` for an address that is not in the PROM window.
    """
    phys = _prom_phys_of(load_address)
    if phys is None:
        return PROM_BASE
    return phys + 0xa0000000


def shdr_segment_vma(segment: SHDRSegment, flash: bytes) -> Optional[int]:
    """The address an O2/IP32 SHDR *segment* executes at, or None if not code.

    Measured, never assumed. A ``seg_type`` 1 code segment carries a crafted
    ``beq $0,$0`` reset trampoline in its first word and runs *in place* from
    the PROM base, so its VMA is ``PROM_BASE + offset`` (why IP32 ``post1`` runs
    at ``0xBFC04400``). A ``seg_type`` 3 code segment is copied to RAM and
    declares its own load address in the first two words of its body; the IP32
    ``firmware`` body starts ``0x81000000, 0x00048e70`` (address, length).
    Non-code segments (``seg_type`` 0) are data and return None.
    """
    if segment.seg_type == 1:
        return PROM_BASE + segment.offset
    if segment.seg_type == 3:
        body = segment.offset + SHDR_SEG_BODY_OFF
        if body + 8 <= len(flash):
            addr = int.from_bytes(flash[body:body + 4], 'big')
            length = int.from_bytes(flash[body + 4:body + 8], 'big')
            if addr and length:
                return addr
    return None


def extract_prom_code(data: bytes, endian: str = "big") -> PromCodeImage:
    """Return the MIPS code slice and load address for a PROM image.

    Plain PROMs are returned whole, based at ``PROM_BASE``. SN0/SN1 containers
    are sliced at ``code_offset`` and based at the translated load address. A
    `promseg_t` segment with the GZIP flag is decompressed first (IO6); the
    decompressed size and the `sum` checksum are verified. Byte-swapped
    (``endian != "big"``) images are normalized after extraction.

    Raises:
        ValueError: if the container magic is present but the header is
            malformed (zero/out-of-range code size, segment past EOF, load
            address outside the PROM region), the segment uses unsupported
            compression (RLE/LZW), gzip fails, or the size/checksum does not
            match the header. Never silently misparses.
    """
    if is_sn0_container(data):
        info = parse_sn0_container(data)
        if info is None:
            raise ValueError("SN0 container magic present but header unreadable")

        comp = info.flags & SN0_SFLAG_COMPMASK
        if comp == SN0_SFLAG_NONE:
            stored_len = info.code_size
        elif comp in (SN0_SFLAG_GZIP, SN0_SFLAG_RLE, SN0_SFLAG_LZW):
            stored_len = info.code_size_c
            if stored_len <= 0:
                raise ValueError(
                    "SN0 segment is compressed but has no compressed length")
        else:
            raise ValueError(
                "SN0 segment compression {} (flags 0x{:x}) is unknown "
                "(NONE, RLE, LZW and GZIP are defined)".format(comp, info.flags))
        if info.code_size <= 0:
            raise ValueError(
                "SN0 container has no code (code_size={}, truncated header?)".format(
                    info.code_size))
        if info.code_offset < SN0_MAGIC_OFFSET:
            raise ValueError(
                "SN0 code_offset 0x{:x} overlaps the container header".format(
                    info.code_offset))
        end = info.code_offset + stored_len
        if end > len(data):
            raise ValueError(
                "SN0 segment 0x{:x}+0x{:x} runs past EOF (file is 0x{:x} bytes, "
                "truncated?)".format(info.code_offset, stored_len, len(data)))
        if _prom_phys_of(info.load_address) is None:
            raise ValueError(
                "SN0 load address 0x{:016x} is outside the PROM address range".format(
                    info.load_address))

        stored = data[info.code_offset:end]
        if comp == SN0_SFLAG_GZIP:
            try:
                code = gzip.decompress(stored)
            except (OSError, EOFError) as exc:
                raise ValueError(
                    "SN0 gzip segment failed to decompress: {}".format(exc))
            if len(code) != info.code_size:
                raise ValueError(
                    "SN0 decompressed size {} != declared length {}".format(
                        len(code), info.code_size))
        elif comp in (SN0_SFLAG_RLE, SN0_SFLAG_LZW):
            try:
                code = (rle_decompress(stored) if comp == SN0_SFLAG_RLE
                        else lzw_decompress(stored))
            except DecompressError as exc:
                raise ValueError(
                    "SN0 compressed segment failed to decompress: {}".format(exc))
            if len(code) != info.code_size:
                raise ValueError(
                    "SN0 decompressed size {} != declared length {}".format(
                        len(code), info.code_size))
        else:
            code = stored

        # promseg_t.sum is a 32-bit additive byte sum of the true segment.
        if info.sum:
            actual_sum = sum(code) & 0xFFFFFFFF
            if actual_sum != info.sum:
                raise ValueError(
                    "SN0 segment checksum mismatch (computed 0x{:x}, header "
                    "0x{:x})".format(actual_sum, info.sum))

        if endian != "big":
            code = normalize_data(code, endian)
        base = prom_code_base(info.load_address)
        comp_name = {SN0_SFLAG_NONE: "none", SN0_SFLAG_RLE: "rle",
                     SN0_SFLAG_LZW: "lzw", SN0_SFLAG_GZIP: "gzip"}.get(
                         comp, "compression {}".format(comp))
        seg_names = ", ".join(s.name for s in info.segments) or info.module_name
        seg_desc = "{} segment(s) [{}]".format(
            len(info.segments) or 1, seg_names)
        extra = ""
        if info.total_size and info.total_size != len(data):
            extra = " (total_size 0x{:x} != file 0x{:x})".format(
                info.total_size, len(data))
        if len(info.segments) > 1:
            extra += " (disassembling segment 0)"
        note = ("SN0 container: module {}, code_off 0x{:x}, size 0x{:x}, "
                "loadaddr 0x{:016x}, base 0x{:08x}, compression {}, {}{}").format(
                    info.module_name, info.code_offset, info.code_size,
                    info.load_address, base, comp_name, seg_desc, extra)
        return PromCodeImage(code, base, info.code_offset, info.code_size,
                             True, info, note, FORMAT_SN_CONTAINER)

    # Not an SN container. Identify the format positively before treating the
    # file as a flat MIPS image:
    #  * O2/IP32 SHDR flash is flat-executable at 0xBFC00000 -- its SHDR segment
    #    headers are crafted branch instructions and the CPU reset vector runs
    #    through them (hw/mips/sgi_o2.c). Only an outer 'PROM' container needs
    #    stripping; the flash image is then the whole file at the PROM base.
    #  * A different container (IO4 JKSW/JFK4) or a file that is not MIPS at all
    #    (x86 BIOS, 68K, ARM, graphics microcode, MIPS ELF) must NOT be
    #    disassembled from offset 0 as if it were a CPU PROM -- that fabricates
    #    output. Refuse with a specific message; callers handle ValueError.
    fmt = detect_prom_format(data)
    if fmt == FORMAT_SHDR:
        off = shdr_flash_offset(data)
        flash = data[off:]           # raw big-endian flash; reset vector @base
        segs = parse_shdr_segments(flash)
        # The whole file is NOT flat-executable at 0xBFC00000: only the first
        # segment (sloader) runs at the reset base; post1 runs in place at
        # base+0x4400 and firmware is copied to 0x81000000 (declared in its own
        # body). Name each segment and its VMA so a lane cannot disassemble
        # firmware at 0xBFC00000 and silently get wrong jump targets.
        parts = []
        for s in segs:
            vma = shdr_segment_vma(s, flash)
            where = " @0x{:08x}".format(vma) if vma is not None else ""
            bad = "" if (s.header_sum_ok and s.body_sum_ok) else " [BAD SUM]"
            parts.append("{} (off 0x{:x}, len 0x{:x}, type {}{}){}".format(
                s.label, s.offset, s.length, s.seg_type, where, bad))
        note = ("O2/IP32 SHDR flash: {} segment(s), flash offset 0x{:x}; "
                "reset/base 0x{:08x} is sloader (segment 0) only -- other "
                "segments run elsewhere: {}").format(
                    len(segs), off, PROM_BASE, "; ".join(parts) or "none")
        if endian != "big":
            flash = normalize_data(flash, endian)
        img = PromCodeImage(flash, PROM_BASE, off, len(flash), False, None,
                            note, FORMAT_SHDR)
        img.shdr_segments = segs
        return img
    if fmt == FORMAT_IO4_JFK4:
        # IO4 'JFK4': a 0x18-byte header then a flat MIPS image. Fields are
        # self-consistent on all 3 library files (load==entry, and the size at
        # 0x0c equals file_size-0x18 exactly). Slice it; never guess if it does
        # not hold, so a malformed copy is refused rather than misparsed.
        off = JFK4_CODE_OFFSET
        size = jfk4_code_size(data)
        base = jfk4_load_address(data)
        if size <= 0 or off + size > len(data):
            raise ValueError(
                "IO4 'JFK4' image has an inconsistent code size (0x{:x}); "
                "refusing to slice it.".format(size))
        code = data[off:off + size]
        note = ("IO4 'JFK4' image: code offset 0x{:x}, size 0x{:x}, load "
                "0x{:08x}").format(off, size, base)
        if endian != "big":
            code = normalize_data(code, endian)
        return PromCodeImage(code, base, off, size, False, None, note,
                             FORMAT_IO4_JFK4)
    if fmt == FORMAT_IO4_JKSW:
        # IO4 'JKSW': evpromhdr_t + seginfo_t (sys/EVEREST/promhdr.h). The entry
        # code is the MASTER segment; slice it. A table that is absent or whose
        # entry segment runs past EOF is refused rather than misparsed.
        segs = parse_jksw(data)
        if not segs:
            raise ValueError(
                "IO4 'JKSW' image: segment table absent or invalid")
        seg = jksw_entry_segment(segs)
        if seg is None or seg.length <= 0 or seg.offset + seg.length > len(data):
            raise ValueError(
                "IO4 'JKSW' image: entry segment 0x{:x}+0x{:x} is invalid or "
                "runs past EOF (truncated?)".format(
                    seg.offset if seg else 0, seg.length if seg else 0))
        code = data[seg.offset:seg.offset + seg.length]
        base = prom_code_base(seg.start_address)
        note = ("IO4 'JKSW' image: {} segment(s); entry type 0x{:x}, off "
                "0x{:x}, size 0x{:x}, start 0x{:016x}, base 0x{:08x}").format(
                    len(segs), seg.type, seg.offset, seg.length,
                    seg.start_address, base)
        # The MASTER segment is uncompressed; the per-CPU images (R4000/TFP/
        # R10000) carry SFLAG_LZW. Decode them here so the compressed segments
        # are consumed and validated (not merely available): a decode failure
        # is a real corruption and refused, not ignored.
        lzw_segs = [s for s in segs if (s.type & 0x6) == 0x4]
        if lzw_segs:
            try:
                decoded = jksw_lzw_segments(data)
            except DecompressError as exc:
                raise ValueError(
                    "IO4 'JKSW' LZW segment failed to decode: {}".format(exc))
            if len(decoded) != len(lzw_segs):
                raise ValueError(
                    "IO4 'JKSW' image: {} LZW segment(s) declared but {} block(s) "
                    "found".format(len(lzw_segs), len(decoded)))
            note += "; {} LZW CPU segment(s) decoded ({} bytes total)".format(
                len(decoded), sum(len(x) for x in decoded))
        if endian != "big":
            code = normalize_data(code, endian)
        return PromCodeImage(code, base, seg.offset, seg.length, False, None,
                             note, FORMAT_IO4_JKSW)
    if fmt == FORMAT_MIPS_VECTOR_SWAPPED:
        # A raw flash dump of a classic MIPS PROM, stored 16-bit word-swapped
        # (e.g. the IP35/Fuel AM29LV160 mainboard PROM: entry 0xBFC00400). Swap
        # the word order to recover the big-endian image; the detector only
        # raises this format on strong evidence, never a heuristic hit.
        code = swap_words16(data)
        note = ("byte-swapped raw flash MIPS PROM (16-bit word swap; base "
                "0x{:08x}); entry 0x{:x}").format(
                    PROM_BASE, extract_entry_point(code, "big"))
        return PromCodeImage(code, PROM_BASE, 0, len(code), False, None,
                             note, FORMAT_MIPS_VECTOR_SWAPPED)
    if fmt in NON_MIPS_FORMATS:
        raise ValueError(
            "{} [{}]: not a raw MIPS CPU PROM. Refusing to disassemble it "
            "as a flat image at 0x{:08x}.".format(
                describe_prom_format(fmt), fmt, PROM_BASE))

    code = data
    if endian != "big":
        code = normalize_data(data, endian)
    return PromCodeImage(code, PROM_BASE, 0, len(code), False, None, "",
                         fmt)


def load_prom_code(filename: str, use_cache: bool = True) -> Optional[PromCodeImage]:
    """Load a PROM file as a code image (SN-container aware).

    Args:
        filename: PROM filename
        use_cache: Whether to use cached raw data

    Returns:
        PromCodeImage, or None if the file is not found.

    Raises:
        ValueError: on a malformed SN0 container header (see extract_prom_code).
    """
    data = load_prom(filename, use_cache)
    if data is None:
        return None
    return extract_prom_code(data, detect_endianness(data))


def _decode_jump_target(word: int) -> Optional[int]:
    """Decode a MIPS ``j``/``jal`` instruction to its target address.

    The classic SGI PROM header is a table of JUMP instructions, so a header
    word is an address only via its decode -- reading it raw (as the old code
    did) yields an instruction encoding, not an address.
    """
    if (word >> 26) in (0x02, 0x03):        # J, JAL
        return 0xB0000000 | ((word & 0x03FFFFFF) << 2)
    return None


def _in_prom_space(addr: int) -> bool:
    return (0x9FC00000 <= addr < 0xA0000000) or (0xBFC00000 <= addr < 0xC0000000)


def extract_entry_point(data: bytes, endian: str) -> int:
    """
    Extract the entry point of a classic SGI PROM.

    The reset entry is the target of the header's first jump instruction (at
    file offset 0; on IP28 the first word is a zero pad and the jump is at +4).
    Measured: every classic PROM jumps to ``0xbfc003c0``. Falls back to
    ``PROM_BASE`` when no jump decodes there (IP26 has no such header).
    """
    read_fn = read_u32_be if endian == "big" else read_u32_le
    for off in (0x00, 0x04):
        if off + 4 <= len(data):
            target = _decode_jump_target(read_fn(data, off))
            if target is not None and _in_prom_space(target):
                return target
    return PROM_BASE


def detect_shdr_header(data: bytes) -> bool:
    """
    Detect SHDR (O2/IP32) PROM header format.

    The magic is ``"SHDR"`` at file offset **0x08** (not 0): the O2 image begins
    ``10 00 00 11 00 00 00 00 53 48 44 52``. Delegates to the format detector so
    there is one source of truth.
    """
    return detect_prom_format(data) == "shdr"


def extract_vectors(data: bytes, endian: str) -> Dict[str, int]:
    """
    Extract the classic SGI PROM header's jump table as real addresses.

    The header is a RUN of 32-bit ``j`` instructions on an 8-byte stride that
    begins at the reset entry (file offset 0; or +4 when offset 0 is a pad, as on
    IP28). Entry 0 jumps to the reset entry (``0xbfc003c0`` on every classic PROM
    measured), the rest to per-machine service handlers. The run ends at the
    first slot that is not a jump -- so a PROM that merely CONTAINS jumps later
    in its boot code (IP26 begins with CP0 setup, `dmtc0`/`ssnop`) does not have
    those jumps reported as vectors. A vector is emitted only when its word
    decodes as a jump into PROM space; returns ``{}`` when there is no such run
    (i.e. no classic header -- IP26 has none).
    """
    vectors: Dict[str, int] = {}
    read_fn = read_u32_be if endian == "big" else read_u32_le

    start = None
    for off in (0x00, 0x04):
        if off + 4 <= len(data):
            t = _decode_jump_target(read_fn(data, off))
            if t is not None and _in_prom_space(t):
                start = off
                break
    if start is None:
        return {}

    off = start
    while off + 4 <= len(data) and off < start + 0x100:
        t = _decode_jump_target(read_fn(data, off))
        if t is None or not _in_prom_space(t):
            break
        name = "reset_vector" if off == start else "vector_0x{:02x}".format(off)
        vectors[name] = t
        off += 8

    return vectors


def get_prom_metadata(filename: str, use_cache: bool = True) -> Optional[PromMetadata]:
    """
    Get metadata for a PROM file.

    Args:
        filename: PROM filename
        use_cache: Whether to use cached metadata

    Returns:
        PromMetadata or None if file not found
    """
    if use_cache and filename in _metadata_cache:
        return _metadata_cache[filename]

    path = get_prom_path(filename)
    if not path:
        return None

    data = load_prom(filename, use_cache)
    if not data:
        return None

    # Compute SHA256
    sha256 = hashlib.sha256(data).hexdigest()

    # Detect platform and endianness
    platform = detect_platform(filename)
    endian = detect_endianness(data)

    # SN0/SN1 containers wrap the MIPS image at code_offset. Record the mapping
    # for callers that disassemble (the code slice is not stored here to keep
    # metadata light). The classic 8-word vector header / entry-point offsets do
    # NOT apply to a container, so those fields stay read from the raw file
    # (where they are the container header, i.e. normally zero/empty).
    is_container = is_sn0_container(data)
    code_offset = code_size = load_address = code_base = 0
    container_entry = 0
    mapping_note = ""
    if is_container:
        try:
            code = extract_prom_code(data, endian)
            code_offset = code.file_offset
            code_size = code.code_size
            code_base = code.load_address
            load_address = code.container.load_address if code.container else 0
            mapping_note = code.mapping_note
            if code.container and code.container.entry:
                container_entry = prom_code_base(code.container.entry)
        except ValueError:
            # Leave fields at 0; extract_prom_code is the strict entry point.
            pass

    # Extract entry point. A container's classic entry-point offset is absent;
    # its real entry is the segment `entry` field (0xA0), mapped to KSEG1.
    if is_container:
        entry_point = container_entry or PROM_BASE
    else:
        entry_point = extract_entry_point(data, endian)

    # Extract part number
    part_number = extract_part_number(filename)

    # Extract vectors (classic PROM header only; containers have none).
    vectors = {} if is_container else extract_vectors(data, endian)

    metadata = PromMetadata(
        filename=filename,
        filepath=path,
        size=len(data),
        sha256=sha256,
        platform=platform,
        endian=endian,
        entry_point=entry_point,
        part_number=part_number,
        vectors=vectors,
        is_container=is_container,
        code_offset=code_offset,
        code_size=code_size,
        load_address=load_address,
        code_base=code_base,
        mapping_note=mapping_note,
    )

    if use_cache:
        _metadata_cache[filename] = metadata

    return metadata


def clear_cache():
    """Clear all caches."""
    _prom_cache.clear()
    _metadata_cache.clear()


def get_prom_summary() -> List[Dict]:
    """
    Get summary of all available PROMs.

    Returns list of dicts with basic info for each PROM.
    """
    summaries = []
    for path in list_prom_files():
        meta = get_prom_metadata(path.name)
        if meta:
            summaries.append({
                "filename": meta.filename,
                "size": meta.size,
                "platform": meta.platform,
                "part_number": meta.part_number,
                "entry_point": f"0x{meta.entry_point:08x}",
                "sha256": meta.sha256[:16] + "...",
            })
    return summaries


def normalize_data(data: bytes, endian: str) -> bytes:
    """
    Normalize byte-swapped PROM data to big-endian.

    Args:
        data: Raw PROM data
        endian: Detected endianness ("big" or "little")

    Returns:
        Big-endian normalized data
    """
    if endian == "big":
        return data

    # Byte swap every 4 bytes
    result = bytearray(len(data))
    for i in range(0, len(data) - 3, 4):
        result[i] = data[i + 3]
        result[i + 1] = data[i + 2]
        result[i + 2] = data[i + 1]
        result[i + 3] = data[i]

    # Handle remaining bytes
    remainder = len(data) % 4
    if remainder:
        result[-remainder:] = data[-remainder:]

    return bytes(result)


def extract_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """
    Extract printable ASCII strings from PROM data.

    Args:
        data: PROM data
        min_length: Minimum string length to include

    Returns:
        List of (offset, string) tuples
    """
    strings = []
    current: List[str] = []
    start_offset = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte < 0x7f:  # Printable ASCII
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append((start_offset, ''.join(current)))
            current = []

    # Don't forget last string
    if len(current) >= min_length:
        strings.append((start_offset, ''.join(current)))

    return strings
