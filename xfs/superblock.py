"""XFS superblock read/write/validate.

Migrated from sgi_mcp/sgi_fs.py lines 473-505, 1620-1631.
"""

import struct

from pyirix.xfs.constants import (
    XFS_SB_MAGIC, XFS_SB_VERSION_4, XFS_SB_VERSION_OKSASHBITS,
    XFSCorruptionError,
)
from pyirix.xfs.ondisk import parse_superblock, pack_superblock


def read_superblock(f, part_offset):
    """Read and parse the XFS superblock at sector 0 of the partition.

    Returns superblock dict or None if magic doesn't match.
    """
    f.seek(part_offset)
    data = f.read(512)
    if len(data) < 200:
        return None

    sb = parse_superblock(data)
    if sb is None:
        return None

    if sb['sb_magicnum'] != XFS_SB_MAGIC:
        return None

    return sb


def write_superblock(f, part_offset, sb):
    """Write the superblock back to disk.

    Writes at sector 0 of the partition. Only overwrites the first 256 bytes.
    """
    data = pack_superblock(sb)
    f.seek(part_offset)
    f.write(data[:256])
    f.flush()


def sash_compatible(sb):
    """Check if superblock version is acceptable to PROM/SASH.

    Returns (accepted: bool, reason: str).
    """
    vn = sb['sb_versionnum']

    if vn in (1, 2, 3):
        return (True, f"Version {vn}: unconditionally accepted")

    if (vn & 0xF) == 4:
        unknown = vn & ~XFS_SB_VERSION_OKSASHBITS
        if unknown == 0:
            return (True, f"Version 4 (0x{vn:04x}): all feature bits accepted by SASH")
        else:
            return (False, f"Version 4 (0x{vn:04x}): unknown feature bits 0x{unknown:04x}")

    return (False, f"Version 0x{vn:04x}: not recognized by SASH")


def zero_log(f, part_offset, sb):
    """Zero the log area to prevent stale journal replay.

    Call after any write modifications to the filesystem.
    """
    logstart = sb.get('sb_logstart', 0)
    logblocks = sb.get('sb_logblocks', 0)
    blocksize = sb['sb_blocksize']

    if logstart == 0 or logblocks == 0:
        return  # external log or no log

    from pyirix.xfs.ondisk import fsblock_to_offset

    log_offset = fsblock_to_offset(sb, part_offset, logstart)
    log_size = logblocks * blocksize

    # Write zeros in 64KB chunks
    chunk = b'\x00' * min(65536, log_size)
    f.seek(log_offset)
    remaining = log_size
    while remaining > 0:
        n = min(len(chunk), remaining)
        f.write(chunk[:n])
        remaining -= n
    f.flush()
