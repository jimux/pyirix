"""Inode allocation via inobt B+tree.

Each AG has one inobt (XFS_IBT_MAGIC) that tracks 64-inode chunks.
Each record: ir_startino(4) + ir_freecount(4) + ir_free(8) = 16 bytes.
ir_free is a 64-bit bitmask: bit N set = inode (ir_startino + N) is free.
"""

import struct

from pyirix.xfs.constants import (
    XFS_AGI_MAGIC, XFS_IBT_MAGIC,
    XFS_INODES_PER_CHUNK, XFS_INOBT_REC_SIZE, XFS_INOBT_KEY_SIZE,
    XFS_INOBT_ALL_FREE,
    XFS_AGI_DADDR, SECTOR_SIZE, NULLAGBLOCK,
    XFSCorruptionError, XFSNoSpaceError,
)
from pyirix.xfs.ondisk import (
    parse_agi, pack_agi,
    parse_inobt_rec, pack_inobt_rec_full,
    agino_to_ino,
)
from pyirix.xfs.btree import BTreeCursor


def read_agi(f, part_offset, sb, agno):
    """Read the AGI header for an allocation group.

    Returns AGI dict or None.
    """
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']
    ag_offset = part_offset + agno * agblocks * blocksize

    f.seek(ag_offset + XFS_AGI_DADDR * SECTOR_SIZE)
    data = f.read(SECTOR_SIZE)
    if len(data) < 296:
        return None

    agi = parse_agi(data)
    if agi is None or agi['agi_magicnum'] != XFS_AGI_MAGIC:
        return None

    return agi


def write_agi(f, part_offset, sb, agno, agi):
    """Write the AGI header back to disk."""
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']
    ag_offset = part_offset + agno * agblocks * blocksize

    data = pack_agi(agi)
    f.seek(ag_offset + XFS_AGI_DADDR * SECTOR_SIZE)
    f.write(data)
    f.flush()


def _inobt_cursor(f, part_offset, sb, agno, agi):
    """Create a BTreeCursor for the inobt."""
    return BTreeCursor(
        f, part_offset, sb,
        root_block=agi['agi_root'],
        agno=agno,
        magic=XFS_IBT_MAGIC,
        key_size=XFS_INOBT_KEY_SIZE,  # ir_startino only
        rec_size=XFS_INOBT_REC_SIZE,
        long_form=False,
    )


def alloc_inode(f, part_offset, sb):
    """Allocate a free inode.

    Searches all AGs for a chunk with free inodes.
    Returns the full inode number, or raises XFSNoSpaceError.
    """
    agcount = sb['sb_agcount']

    for agno in range(agcount):
        agi = read_agi(f, part_offset, sb, agno)
        if agi is None:
            continue

        if agi['agi_freecount'] == 0:
            continue

        # Walk the inobt looking for a chunk with free inodes
        cur = _inobt_cursor(f, part_offset, sb, agno, agi)

        for rec_data in cur.walk_all():
            rec = parse_inobt_rec(rec_data)
            if rec['ir_freecount'] <= 0:
                continue

            # Find a free bit in ir_free
            free_mask = rec['ir_free']
            for bit in range(XFS_INODES_PER_CHUNK):
                if free_mask & (1 << bit):
                    # Found free inode
                    agino = rec['ir_startino'] + bit

                    # Clear the bit (mark as allocated)
                    rec['ir_free'] &= ~(1 << bit)
                    rec['ir_freecount'] -= 1

                    # Update the record in the B+tree
                    _update_inobt_rec(f, part_offset, sb, agno, agi, rec)

                    # Update AGI
                    agi['agi_freecount'] -= 1
                    agi['agi_newino'] = agino
                    write_agi(f, part_offset, sb, agno, agi)

                    # Update superblock
                    sb['sb_ifree'] -= 1

                    # Zero the on-disk inode
                    _zero_inode(f, part_offset, sb, agno, agino)

                    return agino_to_ino(sb, agno, agino)

    # No free inodes in any existing chunk — allocate a new chunk
    return _alloc_new_chunk(f, part_offset, sb)


def free_inode(f, part_offset, sb, ino):
    """Free an inode back to its AG.

    Sets the bit in ir_free, updates counters, zeros the on-disk inode.
    """
    from pyirix.xfs.ondisk import ino_to_agno, ino_to_agino

    agno = ino_to_agno(sb, ino)
    agino = ino_to_agino(sb, ino)

    agi = read_agi(f, part_offset, sb, agno)
    if agi is None:
        raise XFSCorruptionError(f"Cannot read AGI for AG {agno}")

    # Find the chunk containing this inode
    chunk_start = (agino // XFS_INODES_PER_CHUNK) * XFS_INODES_PER_CHUNK
    bit = agino - chunk_start

    cur = _inobt_cursor(f, part_offset, sb, agno, agi)
    if not cur.lookup_eq(struct.pack('>I', chunk_start)):
        raise XFSCorruptionError(f"Inobt record not found for chunk {chunk_start}")

    rec_data = cur.get_rec()
    rec = parse_inobt_rec(rec_data)

    if rec['ir_free'] & (1 << bit):
        raise XFSCorruptionError(f"Inode {ino} is already free")

    # Set the bit
    rec['ir_free'] |= (1 << bit)
    rec['ir_freecount'] += 1

    # Update record
    _update_inobt_rec(f, part_offset, sb, agno, agi, rec)

    # Update AGI
    agi['agi_freecount'] += 1
    write_agi(f, part_offset, sb, agno, agi)

    # Update superblock
    sb['sb_ifree'] += 1

    # Zero the on-disk inode
    _zero_inode(f, part_offset, sb, agno, agino)


def _update_inobt_rec(f, part_offset, sb, agno, agi, rec):
    """Update an inobt record by finding and replacing it."""
    cur = _inobt_cursor(f, part_offset, sb, agno, agi)
    if cur.lookup_eq(struct.pack('>I', rec['ir_startino'])):
        new_rec = pack_inobt_rec_full(rec)
        cur.update_rec(new_rec)


def _zero_inode(f, part_offset, sb, agno, agino):
    """Zero an on-disk inode."""
    from pyirix.xfs.ondisk import ino_to_offset, agino_to_ino

    full_ino = agino_to_ino(sb, agno, agino)
    offset = ino_to_offset(sb, full_ino, part_offset)
    inodesize = sb['sb_inodesize']

    f.seek(offset)
    f.write(b'\x00' * inodesize)
    f.flush()


def _alloc_new_chunk(f, part_offset, sb):
    """Allocate a new 64-inode chunk when all existing chunks are full.

    Each chunk needs inode_chunk_blocks consecutive blocks.
    For 4KB blocks with 256B inodes: 64 * 256 / 4096 = 4 blocks.
    """
    from pyirix.xfs.alloc import alloc_block

    inodesize = sb['sb_inodesize']
    blocksize = sb['sb_blocksize']
    inodes_per_block = blocksize // inodesize
    chunk_blocks = XFS_INODES_PER_CHUNK // inodes_per_block

    agcount = sb['sb_agcount']

    for agno in range(agcount):
        try:
            ag, agbno, count = alloc_block(f, part_offset, sb, chunk_blocks, agno=agno)
        except XFSNoSpaceError:
            continue

        # Zero the allocated blocks
        ag_offset = part_offset + ag * sb['sb_agblocks'] * blocksize
        disk_off = ag_offset + agbno * blocksize
        f.seek(disk_off)
        f.write(b'\x00' * (chunk_blocks * blocksize))
        f.flush()

        # Create inobt record — all 64 inodes free except the first one we'll allocate
        startino = agbno * inodes_per_block  # AG-relative inode number
        rec = {
            'ir_startino': startino,
            'ir_freecount': XFS_INODES_PER_CHUNK - 1,
            'ir_free': XFS_INOBT_ALL_FREE & ~1,  # bit 0 = allocated
        }

        # Insert into inobt
        agi = read_agi(f, part_offset, sb, agno)
        cur = _inobt_cursor(f, part_offset, sb, agno, agi)

        def _btree_alloc(ag_num):
            raise XFSNoSpaceError("B+tree split during inode alloc — not implemented")

        rec_data = pack_inobt_rec_full(rec)
        cur.lookup_ge(struct.pack('>I', startino))
        cur.insert_rec(rec_data, alloc_fn=_btree_alloc)

        # Update AGI
        agi['agi_count'] += XFS_INODES_PER_CHUNK
        agi['agi_freecount'] += XFS_INODES_PER_CHUNK - 1
        agi['agi_newino'] = startino
        write_agi(f, part_offset, sb, agno, agi)

        # Update superblock
        sb['sb_icount'] += XFS_INODES_PER_CHUNK
        sb['sb_ifree'] += XFS_INODES_PER_CHUNK - 1

        return agino_to_ino(sb, agno, startino)

    raise XFSNoSpaceError("No space for new inode chunk in any AG")
