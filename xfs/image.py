"""Disk image I/O: raw/qcow2, SGI volume header, partition detection.

Migrated from sgi_mcp/sgi_fs.py lines 74-232.
"""

import os
import struct
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from pyirix.xfs.constants import (
    SECTOR_SIZE, QCOW2_MAGIC, VHMAGIC, NVDIR, NPARTAB,
    PTYPE_EFS, PTYPE_SYSV, PTYPE_XFS, XFS_SB_MAGIC,
)

# EFS magic (only needed for detect_filesystem)
_EFS_MAGIC = 0x072959
_EFS_MAGIC_NEW = 0x07295A
_EFS_BLOCK_SIZE = 512


def _find_qemu_img():
    """Find qemu-img binary in known build dirs or PATH."""
    candidates = [
        Path('/workspace/qemu/build-linux/qemu-img'),
        Path('/workspace/qemu/build/qemu-img'),
        Path('/workspace/qemu/build-mac/qemu-img'),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return 'qemu-img'


def is_qcow2(path):
    """Check if file is qcow2 format."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == QCOW2_MAGIC
    except (IOError, OSError):
        return False


@contextmanager
def open_disk_image(path, writable=False):
    """Open a disk image for reading/writing. Handles raw and qcow2.

    Yields an open file object positioned at byte 0.
    For qcow2: converts to temporary raw, writes back on close if writable.
    """
    path = str(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Disk image not found: {path}")

    if is_qcow2(path):
        qemu_img = _find_qemu_img()
        tmpdir = tempfile.mkdtemp(prefix='xfs_')
        tmp_raw = os.path.join(tmpdir, 'disk.raw')
        try:
            subprocess.run(
                [qemu_img, 'convert', '-O', 'raw', path, tmp_raw],
                check=True, capture_output=True, timeout=120
            )
            with open(tmp_raw, 'r+b' if writable else 'rb') as f:
                yield f
                if writable:
                    f.flush()
                    subprocess.run(
                        [qemu_img, 'convert', '-O', 'qcow2', tmp_raw, path],
                        check=True, capture_output=True, timeout=120
                    )
        finally:
            try:
                os.unlink(tmp_raw)
                os.rmdir(tmpdir)
            except OSError:
                pass
    else:
        with open(path, 'r+b' if writable else 'rb') as f:
            yield f


def read_vh(f):
    """Read and parse SGI volume header from file position 0.

    Returns dict with 'magic', 'bootfile', 'vd' (volume dir), 'pt' (partition table),
    or None if magic doesn't match.
    """
    f.seek(0)
    data = f.read(512)
    if len(data) < 512:
        return None

    magic = struct.unpack('>I', data[0:4])[0]
    if magic != VHMAGIC:
        return None

    vh = {'magic': magic}
    vh['bootfile'] = data[8:24].split(b'\x00')[0].decode('ascii', errors='replace')

    dp_offset = 24
    dp_size = 48

    # Volume directory: 15 entries, each 16 bytes
    vd_offset = dp_offset + dp_size
    vh['vd'] = []
    for i in range(NVDIR):
        off = vd_offset + i * 16
        name = data[off:off + 8].split(b'\x00')[0].decode('ascii', errors='replace')
        lbn, nbytes = struct.unpack('>ii', data[off + 8:off + 16])
        vh['vd'].append({'name': name, 'lbn': lbn, 'nbytes': nbytes})

    # Partition table: 16 entries, each 12 bytes
    pt_offset = vd_offset + NVDIR * 16
    vh['pt'] = []
    for i in range(NPARTAB):
        off = pt_offset + i * 12
        nblks, firstlbn, ptype = struct.unpack('>iii', data[off:off + 12])
        vh['pt'].append({'nblks': nblks, 'firstlbn': firstlbn, 'type': ptype})

    return vh


def find_partition(f, ptype_wanted):
    """Find a partition by type. Returns (byte_offset, byte_size) or None."""
    vh = read_vh(f)
    if not vh:
        return None
    for pt in vh['pt']:
        if pt['type'] == ptype_wanted and pt['nblks'] > 0:
            return (pt['firstlbn'] * SECTOR_SIZE, pt['nblks'] * SECTOR_SIZE)
    return None


def find_xfs_partition(f):
    """Find the XFS partition. Returns (byte_offset, byte_size) or None."""
    return find_partition(f, PTYPE_XFS)


def detect_filesystem(f, part_offset):
    """Detect filesystem type at given partition offset.

    Returns 'efs', 'xfs', or None.
    """
    # Check EFS superblock at block 1
    f.seek(part_offset + _EFS_BLOCK_SIZE)
    data = f.read(32)
    if len(data) >= 32:
        magic = struct.unpack('>I', data[28:32])[0]
        if magic in (_EFS_MAGIC, _EFS_MAGIC_NEW):
            return 'efs'

    # Check XFS superblock at sector 0
    f.seek(part_offset)
    data = f.read(4)
    if len(data) >= 4:
        magic = struct.unpack('>I', data[0:4])[0]
        if magic == XFS_SB_MAGIC:
            return 'xfs'

    return None
