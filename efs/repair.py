"""pyirix.efs.repair — EFS diagnostics and repair.

  check_efs()             — read-only fsck-style inspection
  verify_checksum()       — recompute the EFS superblock checksum
  recover_superblock()    — rewrite a corrupt primary superblock from the
                            replica (every EFS has a backup SB at fs_size-1)

The primary superblock lives at block 1 of the partition; a replica lives at
block (fs_replsb). The 32-bit checksum (offset 88) is an XOR of the big-endian
16-bit words over bytes 0..87 with a left-rotate after each word (per the IRIX
kernel efs_vfsops.c).
"""

import struct

from pyirix.efs.reader import (
    find_efs_partition, read_superblock, read_inode, read_dir_entries,
    EFS_MAGIC, EFS_MAGIC_NEW, EFS_BLOCK_SIZE, EFS_ROOT_INODE, S_IFMT, S_IFDIR,
)
from pyirix.xfs.repair import Finding, CheckReport   # reuse the report types


def compute_checksum(sb_bytes):
    """EFS superblock checksum over bytes 0..87 (XOR of BE 16-bit words,
    rotate-left 1 after each)."""
    checksum = 0
    for i in range(0, 88, 2):
        word = struct.unpack('>H', sb_bytes[i:i + 2])[0]
        checksum ^= word
        sign = 1 if (checksum & 0x80000000) else 0
        checksum = ((checksum << 1) | sign) & 0xFFFFFFFF
    return checksum


def verify_checksum(f, part_offset):
    """Return (ok, stored, computed) for the primary superblock checksum."""
    f.seek(part_offset + EFS_BLOCK_SIZE)
    sb_bytes = f.read(512)
    stored = struct.unpack('>I', sb_bytes[88:92])[0]
    computed = compute_checksum(sb_bytes)
    return (stored == computed, stored, computed)


def _looks_like_sb(block):
    if len(block) < 32:
        return False
    magic = struct.unpack('>I', block[28:32])[0]
    return magic in (EFS_MAGIC, EFS_MAGIC_NEW)


def find_replica_superblock(f, part_offset):
    """Locate a valid replica superblock. Returns (byte_offset, block_no) or None.

    Uses fs_replsb / fs_size from the primary if it is readable; otherwise scans
    the partition for a block carrying the EFS magic.
    """
    sb = read_superblock(f, part_offset)
    if sb is not None:
        for blk in (sb.get('fs_replsb'), sb.get('fs_size', 0) - 1):
            if blk and blk > 1:
                off = part_offset + blk * EFS_BLOCK_SIZE
                f.seek(off)
                if _looks_like_sb(f.read(512)):
                    return (off, blk)
    # Scan (primary unreadable): superblock copies carry magic at byte 28.
    import os
    size = os.fstat(f.fileno()).st_size
    pos = part_offset + 2 * EFS_BLOCK_SIZE
    while pos + 512 <= size:
        f.seek(pos)
        if _looks_like_sb(f.read(512)):
            return (pos, (pos - part_offset) // EFS_BLOCK_SIZE)
        pos += EFS_BLOCK_SIZE
    return None


def check_efs(f):
    """Read-only structural check of an EFS disc image. Returns a CheckReport."""
    r = CheckReport()
    part = find_efs_partition(f)
    if not part:
        r.add('FAIL', 'partition', "no EFS partition found (volume header / magic scan)")
        return r
    part_offset, part_size = part
    r.add('PASS', 'partition', f"EFS partition at byte {part_offset} ({part_size} bytes)")

    f.seek(part_offset + EFS_BLOCK_SIZE)
    sb_bytes = f.read(512)
    magic = struct.unpack('>I', sb_bytes[28:32])[0]
    if magic not in (EFS_MAGIC, EFS_MAGIC_NEW):
        r.add('FAIL', 'sb_magic', f"primary superblock magic {magic:#08x} invalid")
        if find_replica_superblock(f, part_offset):
            r.add('INFO', 'replica', "a valid replica superblock is available")
        return r
    r.add('PASS', 'sb_magic', "superblock magic OK")

    ok, stored, computed = verify_checksum(f, part_offset)
    if ok:
        r.add('PASS', 'checksum', f"superblock checksum OK ({stored:#010x})")
    else:
        r.add('FAIL', 'checksum',
              f"superblock checksum {stored:#010x} != computed {computed:#010x}")

    sb = read_superblock(f, part_offset)
    fs_size = sb['fs_size']
    if fs_size != sb['fs_firstcg'] + sb['fs_cgfsize'] * sb['fs_ncg']:
        r.add('WARN', 'geometry',
              "fs_size != fs_firstcg + fs_cgfsize*fs_ncg (EFS invariant)")
    else:
        r.add('PASS', 'geometry', "cylinder-group geometry consistent")

    root = read_inode(f, part_offset, sb, EFS_ROOT_INODE)
    if root is None or (root['mode'] & S_IFMT) != S_IFDIR:
        r.add('FAIL', 'root_inode', "root inode missing or not a directory")
    else:
        n = len(read_dir_entries(f, part_offset, sb, root))
        r.add('PASS', 'root_inode', f"root directory readable ({n} entries)")
    return r


def recover_superblock(f, part_offset, dry_run=True):
    """Rewrite a corrupt primary superblock from the replica."""
    f.seek(part_offset + EFS_BLOCK_SIZE)
    if _looks_like_sb(f.read(512)):
        return {'changed': False, 'reason': 'primary superblock magic is valid'}
    rep = find_replica_superblock(f, part_offset)
    if not rep:
        return {'changed': False, 'reason': 'no replica superblock found'}
    off, blk = rep
    if not dry_run:
        f.seek(off)
        good = f.read(512)
        f.seek(part_offset + EFS_BLOCK_SIZE)
        f.write(good)
        f.flush()
    return {'changed': not dry_run, 'source_block': blk,
            'reason': f'recovered primary superblock from replica at block {blk}'}
