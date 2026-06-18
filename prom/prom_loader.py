# SGI PROM Comparative Analysis - PROM Loader
"""
PROM loading with caching, platform detection, and metadata extraction.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from functools import lru_cache

from .config import (
    PROM_DIR, PROM_BASE, ENTRY_POINT_OFFSET,
    detect_platform, PLATFORMS, prom_offset_to_addr
)


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


# Cache for loaded PROM data
_prom_cache: Dict[str, bytes] = {}
_metadata_cache: Dict[str, PromMetadata] = {}


def list_prom_files() -> List[Path]:
    """List all PROM binary files in the samples directory."""
    proms = list(PROM_DIR.glob("*.bin"))
    return sorted(proms, key=lambda p: p.name.lower())


def get_prom_path(filename: str) -> Optional[Path]:
    """Get full path for a PROM filename."""
    # Try exact match
    path = PROM_DIR / filename
    if path.exists():
        return path

    # Try case-insensitive match
    for p in PROM_DIR.glob("*.bin"):
        if p.name.lower() == filename.lower():
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


def extract_entry_point(data: bytes, endian: str) -> int:
    """
    Extract entry point from PROM header.

    The entry point is typically at offset 0x18 in the PROM header.
    """
    if len(data) < ENTRY_POINT_OFFSET + 4:
        return PROM_BASE  # Default to PROM base

    if endian == "big":
        entry = read_u32_be(data, ENTRY_POINT_OFFSET)
    else:
        entry = read_u32_le(data, ENTRY_POINT_OFFSET)

    # Validate entry point is in PROM range
    if 0xbfc00000 <= entry < 0xc0000000:
        return entry
    elif 0x9fc00000 <= entry < 0xa0000000:
        return entry

    # If not valid, return PROM base
    return PROM_BASE


def detect_shdr_header(data: bytes) -> bool:
    """
    Detect SHDR (O2/Octane) PROM header format.

    These PROMs have a different header structure.
    """
    if len(data) < 16:
        return False

    # SHDR magic at start
    if data[0:4] == b'SHDR':
        return True

    return False


def extract_vectors(data: bytes, endian: str) -> Dict[str, int]:
    """
    Extract known vectors from PROM.

    Returns dict mapping vector name to address.
    """
    vectors = {}
    read_fn = read_u32_be if endian == "big" else read_u32_le

    # Vector table locations (offsets and names)
    vector_offsets = [
        (0x00, "reset_vector"),
        (0x04, "version"),
        (0x08, "length"),
        (0x0c, "checksum"),
        (0x10, "platform_id"),
        (0x14, "flags"),
        (0x18, "entry_point"),
        (0x1c, "bss_start"),
        (0x20, "bss_end"),
        (0x80, "printf_vector"),
        (0x84, "restart_vector"),
        (0x88, "reinit_vector"),
        (0x8c, "reboot_vector"),
    ]

    for offset, name in vector_offsets:
        if offset + 4 <= len(data):
            val = read_fn(data, offset)
            if val != 0:
                vectors[name] = val

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

    # Extract entry point
    entry_point = extract_entry_point(data, endian)

    # Extract part number
    part_number = extract_part_number(filename)

    # Extract vectors
    vectors = extract_vectors(data, endian)

    metadata = PromMetadata(
        filename=filename,
        filepath=path,
        size=len(data),
        sha256=sha256,
        platform=platform,
        endian=endian,
        entry_point=entry_point,
        part_number=part_number,
        vectors=vectors
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
    current = []
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
