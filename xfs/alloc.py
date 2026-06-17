"""Block allocation via AG free space B+trees (bnobt and cntbt).

Each AG has two free space B+trees:
- bnobt (XFS_ABTB_MAGIC): records sorted by block number
- cntbt (XFS_ABTC_MAGIC): records sorted by (count, block number)

Both use short-form B+tree blocks with 8-byte records:
  ar_startblock(4) + ar_blockcount(4)
"""

import struct

from pyirix.xfs.constants import (
    XFS_AGF_MAGIC, XFS_ABTB_MAGIC, XFS_ABTC_MAGIC,
    XFS_ALLOC_REC_SIZE, XFS_ALLOC_KEY_SIZE, XFS_ALLOC_PTR_SIZE,
    XFS_AGF_DADDR, SECTOR_SIZE, NULLAGBLOCK,
    XFSCorruptionError, XFSNoSpaceError,
)
from pyirix.xfs.ondisk import parse_agf, pack_agf, parse_alloc_rec, pack_alloc_rec
from pyirix.xfs.btree import BTreeCursor


def read_agf(f, part_offset, sb, agno):
    """Read the AGF header for an allocation group.

    Returns AGF dict or None.
    """
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']
    ag_offset = part_offset + agno * agblocks * blocksize

    # AGF is at sector 1 of the AG
    f.seek(ag_offset + XFS_AGF_DADDR * SECTOR_SIZE)
    data = f.read(SECTOR_SIZE)
    if len(data) < 60:
        return None

    agf = parse_agf(data)
    if agf is None or agf['agf_magicnum'] != XFS_AGF_MAGIC:
        return None

    return agf


def write_agf(f, part_offset, sb, agno, agf):
    """Write the AGF header back to disk."""
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']
    ag_offset = part_offset + agno * agblocks * blocksize

    data = pack_agf(agf)
    f.seek(ag_offset + XFS_AGF_DADDR * SECTOR_SIZE)
    f.write(data)
    f.flush()


def _bno_cursor(f, part_offset, sb, agno, agf):
    """Create a BTreeCursor for the bnobt (by block number)."""
    return BTreeCursor(
        f, part_offset, sb,
        root_block=agf['agf_bno_root'],
        agno=agno,
        magic=XFS_ABTB_MAGIC,
        key_size=4,  # ar_startblock
        rec_size=XFS_ALLOC_REC_SIZE,
        long_form=False,
    )


def _cnt_cursor(f, part_offset, sb, agno, agf):
    """Create a BTreeCursor for the cntbt (by count).

    Note: cntbt sorts by (blockcount, startblock) — we use blockcount as key.
    """
    return BTreeCursor(
        f, part_offset, sb,
        root_block=agf['agf_cnt_root'],
        agno=agno,
        magic=XFS_ABTC_MAGIC,
        key_size=4,  # ar_blockcount as primary key
        rec_size=XFS_ALLOC_REC_SIZE,
        long_form=False,
    )


class CntBTreeCursor(BTreeCursor):
    """Specialized cursor for cntbt that sorts by (count, startblock)."""

    def _compare_keys(self, key1, key2):
        """Compare cntbt keys: first by count, then by startblock.

        For the cntbt, records are 8 bytes (startblock(4) + blockcount(4)),
        but they're sorted by blockcount first, then startblock.
        When used as keys, the key_size is 4 (just blockcount for search),
        but we need the full record for precise ordering.
        """
        if len(key1) == 4:
            v1 = struct.unpack('>I', key1)[0]
            v2 = struct.unpack('>I', key2)[0]
            return -1 if v1 < v2 else (1 if v1 > v2 else 0)

        # Full 8-byte record comparison: by count then startblock
        if len(key1) == 8:
            s1, c1 = struct.unpack('>II', key1)
            s2, c2 = struct.unpack('>II', key2)
            if c1 != c2:
                return -1 if c1 < c2 else 1
            return -1 if s1 < s2 else (1 if s1 > s2 else 0)

        return super()._compare_keys(key1, key2)

    def _extract_key_from_rec(self, rec_data):
        """For cntbt, the sort key is blockcount (bytes 4-8)."""
        return rec_data[4:8]


def _cnt_cursor_proper(f, part_offset, sb, agno, agf):
    """Create a CntBTreeCursor for proper cntbt ordering."""
    return CntBTreeCursor(
        f, part_offset, sb,
        root_block=agf['agf_cnt_root'],
        agno=agno,
        magic=XFS_ABTC_MAGIC,
        key_size=4,  # blockcount as search key
        rec_size=XFS_ALLOC_REC_SIZE,
        long_form=False,
    )


def alloc_block(f, part_offset, sb, count, agno=None):
    """Allocate contiguous blocks from an AG.

    Returns (agno, agbno, actual_count) or raises XFSNoSpaceError.
    Searches for an extent >= count in the cntbt.
    """
    agcount = sb['sb_agcount']

    if agno is not None:
        ags_to_try = [agno]
    else:
        ags_to_try = range(agcount)

    for ag in ags_to_try:
        agf = read_agf(f, part_offset, sb, ag)
        if agf is None:
            continue

        if agf['agf_freeblks'] < count:
            continue

        # Search cntbt for extent >= count
        cnt_cur = _cnt_cursor_proper(f, part_offset, sb, ag, agf)
        if not cnt_cur.lookup_ge(struct.pack('>I', count)):
            continue

        rec = cnt_cur.get_rec()
        if rec is None:
            continue

        ar_startblock, ar_blockcount = parse_alloc_rec(rec)

        if ar_blockcount < count:
            continue

        # Found a suitable extent — remove/shrink it
        _remove_free_extent(f, part_offset, sb, ag, agf, ar_startblock, ar_blockcount)

        # If extent is larger than needed, put remainder back
        if ar_blockcount > count:
            remainder_start = ar_startblock + count
            remainder_count = ar_blockcount - count
            _add_free_extent(f, part_offset, sb, ag, agf, remainder_start, remainder_count)

        # Update AGF counters
        agf['agf_freeblks'] -= count
        if agf['agf_longest'] == ar_blockcount:
            # Longest might have changed — find new longest
            agf['agf_longest'] = _find_longest(f, part_offset, sb, ag, agf)
        write_agf(f, part_offset, sb, ag, agf)

        # Update superblock
        sb['sb_fdblocks'] -= count

        return (ag, ar_startblock, count)

    raise XFSNoSpaceError(f"No free space for {count} blocks")


def free_block(f, part_offset, sb, agno, agbno, count):
    """Free blocks back to an AG.

    Inserts the extent into both bnobt and cntbt, merging with adjacent
    free extents if possible.
    """
    agf = read_agf(f, part_offset, sb, agno)
    if agf is None:
        raise XFSCorruptionError(f"Cannot read AGF for AG {agno}")

    # Check for adjacent free extents to merge
    merge_start = agbno
    merge_count = count

    bno_cur = _bno_cursor(f, part_offset, sb, agno, agf)

    # Check for left neighbor
    if bno_cur.lookup_le(struct.pack('>I', agbno)):
        rec = bno_cur.get_rec()
        if rec:
            left_start, left_count = parse_alloc_rec(rec)
            if left_start + left_count == agbno:
                # Merge with left
                _remove_free_extent(f, part_offset, sb, agno, agf, left_start, left_count)
                merge_start = left_start
                merge_count += left_count

    # Re-read AGF (may have changed)
    agf = read_agf(f, part_offset, sb, agno)

    # Check for right neighbor
    bno_cur = _bno_cursor(f, part_offset, sb, agno, agf)
    right_agbno = merge_start + merge_count
    if bno_cur.lookup_ge(struct.pack('>I', right_agbno)):
        rec = bno_cur.get_rec()
        if rec:
            right_start, right_count = parse_alloc_rec(rec)
            if right_start == right_agbno:
                # Merge with right
                _remove_free_extent(f, part_offset, sb, agno, agf, right_start, right_count)
                merge_count += right_count
                agf = read_agf(f, part_offset, sb, agno)

    # Add the merged extent
    _add_free_extent(f, part_offset, sb, agno, agf, merge_start, merge_count)

    # Update counters
    agf['agf_freeblks'] += count
    if merge_count > agf['agf_longest']:
        agf['agf_longest'] = merge_count
    write_agf(f, part_offset, sb, agno, agf)

    sb['sb_fdblocks'] += count


def alloc_blocks_for_file(f, part_offset, sb, count, agno=None):
    """Allocate blocks for a file, possibly returning multiple extents.

    Returns list of (fsblock, extent_count) tuples.
    """
    from pyirix.xfs.ondisk import agbno_to_fsblock

    remaining = count
    allocations = []

    while remaining > 0:
        try:
            ag, agbno, got = alloc_block(f, part_offset, sb, remaining, agno=agno)
        except XFSNoSpaceError:
            if remaining > 1:
                # Try smaller allocations
                try:
                    ag, agbno, got = alloc_block(f, part_offset, sb, 1, agno=agno)
                except XFSNoSpaceError:
                    raise XFSNoSpaceError(
                        f"Cannot allocate remaining {remaining} blocks")
            else:
                raise

        fsblock = agbno_to_fsblock(sb, ag, agbno)
        allocations.append((fsblock, got))
        remaining -= got

    return allocations


def _remove_free_extent(f, part_offset, sb, agno, agf, startblock, blockcount):
    """Remove a free extent from both bnobt and cntbt."""
    # Remove from bnobt
    bno_cur = _bno_cursor(f, part_offset, sb, agno, agf)
    if bno_cur.lookup_eq(struct.pack('>I', startblock)):
        bno_cur.delete_rec()

    # Remove from cntbt — need to find exact record
    cnt_cur = _cnt_cursor_proper(f, part_offset, sb, agno, agf)
    if cnt_cur.lookup_ge(struct.pack('>I', blockcount)):
        # Walk through records with matching count to find our startblock
        while True:
            rec = cnt_cur.get_rec()
            if rec is None:
                break
            s, c = parse_alloc_rec(rec)
            if c != blockcount:
                break
            if s == startblock:
                cnt_cur.delete_rec()
                return
            if not cnt_cur.increment():
                break


def _add_free_extent(f, part_offset, sb, agno, agf, startblock, blockcount):
    """Add a free extent to both bnobt and cntbt."""
    rec = pack_alloc_rec(startblock, blockcount)

    # We need a block allocator for potential splits
    def _btree_alloc(agno):
        # Simple: use agf_fllast or find a free block in the AG
        # This is a simplified approach — real XFS uses the AGFL
        raise XFSNoSpaceError("B+tree split during free — not implemented")

    # Insert into bnobt
    bno_cur = _bno_cursor(f, part_offset, sb, agno, agf)
    bno_cur.lookup_ge(struct.pack('>I', startblock))
    bno_cur.insert_rec(rec, alloc_fn=_btree_alloc)

    # Insert into cntbt
    cnt_cur = _cnt_cursor_proper(f, part_offset, sb, agno, agf)
    cnt_cur.lookup_ge(struct.pack('>I', blockcount))
    cnt_cur.insert_rec(rec, alloc_fn=_btree_alloc)


def _find_longest(f, part_offset, sb, agno, agf):
    """Find the longest free extent in the cntbt."""
    cnt_cur = _cnt_cursor_proper(f, part_offset, sb, agno, agf)

    longest = 0
    for rec_data in cnt_cur.walk_all():
        _, blockcount = parse_alloc_rec(rec_data)
        if blockcount > longest:
            longest = blockcount

    return longest
