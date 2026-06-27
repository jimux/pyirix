"""XFS inode-buffer integrity scan (corruption detection).

Walks every inode slot — allocated AND free — of every inobt chunk and verifies
``di_magic == 'IN'`` (``XFS_DINODE_MAGIC``). This catches the block-level
inode-buffer corruption the IRIX kernel reports as
``Bad magic # 0x0 in XFS inode buffer ...`` — the failure class that, on a
force-killed dev disk, replays into ``EFSCORRUPTED`` on every boot.

Why scan FREE slots too (the load-bearing IRIX insight): IRIX's
``xfs_inobp_bwcheck()`` validates *every* inode in a buffer on bwrite, allocated
or not — ``xfs_ialloc_ag_alloc`` initializes the whole 64-inode chunk, so even
free slots carry 'IN' magic. A correct corruption check therefore verifies all
64 slots per chunk (not just allocated ones) and reports allocated- vs
free-slot mismatches separately.

Extracted from the one-off ``scan_inode_buffers.py`` (archive/one_offs/).
"""
from .image import open_disk_image, find_xfs_partition
from .superblock import read_superblock
from .ialloc import read_agi, _inobt_cursor
from .ondisk import parse_inobt_rec, agino_to_ino
from .constants import XFS_DINODE_MAGIC, XFS_INODES_PER_CHUNK


def scan_inode_magic(f, part_offset, sb, check_free=True):
    """Scan every inode slot's ``di_magic`` in an already-open XFS image.

    Returns a dict ``{chunks, allocated, free, bad_alloc, bad_free}`` where each
    ``bad_*`` entry is ``(fs_ino, byte_pos, magic, fs_block)``.
    """
    inode_size = sb['sb_inodesize']
    agblocks = sb['sb_agblocks']
    bsize = sb['sb_blocksize']
    bad_alloc, bad_free = [], []
    chunks = allocated = free = 0
    for agno in range(sb['sb_agcount']):
        agi = read_agi(f, part_offset, sb, agno)
        if agi is None:
            continue
        cur = _inobt_cursor(f, part_offset, sb, agno, agi)
        for rec_data in cur.walk_all():
            rec = parse_inobt_rec(rec_data)
            chunks += 1
            startino = rec['ir_startino']
            freemask = rec['ir_free']
            for bit in range(XFS_INODES_PER_CHUNK):
                is_free = bool(freemask & (1 << bit))
                if is_free:
                    free += 1
                    if not check_free:
                        continue
                else:
                    allocated += 1
                agino = startino + bit
                fs_ino = agino_to_ino(sb, agno, agino)
                pos_in_ag = agino * inode_size
                fs_block = agno * agblocks + pos_in_ag // bsize
                byte_pos = part_offset + fs_block * bsize + pos_in_ag % bsize
                f.seek(byte_pos)
                raw = f.read(2)
                magic = int.from_bytes(raw, 'big') if len(raw) >= 2 else -1
                if magic != XFS_DINODE_MAGIC:
                    (bad_free if is_free else bad_alloc).append(
                        (fs_ino, byte_pos, magic, fs_block))
    return {'chunks': chunks, 'allocated': allocated, 'free': free,
            'bad_alloc': bad_alloc, 'bad_free': bad_free}


def scan_image(path, check_free=True):
    """Open an XFS image (raw or qcow2) and scan inode magic.

    Returns the :func:`scan_inode_magic` dict plus ``ok`` (True iff no bad
    slots), or ``{'error': ...}`` if no XFS partition is found.
    """
    with open_disk_image(path) as f:
        part = find_xfs_partition(f)
        if not part:
            return {'error': 'no XFS partition found'}
        part_offset = part[0]
        sb = read_superblock(f, part_offset)
        if sb is None:
            return {'error': 'cannot read superblock'}
        res = scan_inode_magic(f, part_offset, sb, check_free=check_free)
    res['ok'] = not (res['bad_alloc'] or res['bad_free'])
    return res
