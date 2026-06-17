"""XFS directory read/write for V1 shortform, V1 leaf, and dir2 block formats.

Read path migrated from sgi_mcp/sgi_fs.py lines 771-972.
Write operations are new.
"""

import struct

from pyirix.xfs.constants import (
    XFS_DINODE_FMT_LOCAL, XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE,
    XFS_DIR_LEAF_MAGIC, XFS_DA_NODE_MAGIC,
    XFS_DIR2_BLOCK_MAGIC, XFS_DIR2_DATA_MAGIC, XFS_DIR2_FREE_TAG,
    XFS_DIR_SF_HDR_SIZE, XFS_DIR_SF_ENTRY_BASE,
    XFS_DIR_LEAF_HDR_SIZE, XFS_DIR_LEAF_ENTRY_SIZE, XFS_DIR_LEAF_NAME_BASE,
    XFS_DIR2_DATA_HDR_SIZE, XFS_DIR2_BLOCK_TAIL_SIZE,
    XFS_DIR2_SF_HDR_SIZE_4, XFS_DIR2_SF_HDR_SIZE_8,
    XFS_DIR2_MAX_SHORT_INUM,
    XFS_DIR2_DATA_DOT_OFFSET, XFS_DIR2_DATA_DOTDOT_OFFSET,
    XFS_DIR2_DATA_FIRST_OFFSET,
    XFS_DIR2_LEAF_ENTRY_SIZE,
    XFS_DIR3_FT_UNKNOWN, XFS_DIR3_FT_REG_FILE, XFS_DIR3_FT_DIR,
    S_IFMT, S_IFDIR, S_IFREG, S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK,
    XFSError, XFSExistsError, XFSPathError,
)
from pyirix.xfs.ondisk import (
    parse_bmbt_rec, fsblock_to_offset, xfs_da_hashname, has_dirv2, has_ftype,
)
from pyirix.xfs.inode import get_extents, get_data_fork, set_data_fork


# ── Read Operations ─────────────────────────────────────────────────

def read_dir_entries(f, part_offset, sb, inode):
    """Read directory entries from an XFS inode.

    Returns list of (name, inode_number) tuples, excluding '.' and '..'.
    """
    fmt = inode['di_format']
    if fmt == XFS_DINODE_FMT_LOCAL:
        return read_dir_sf(inode, sb)
    else:
        return _read_dir_block(f, part_offset, sb, inode)


def read_dir_sf(inode, sb=None):
    """Read shortform directory entries from inline data.

    Dispatches to V1 or dir2 shortform based on superblock version.
    V1 format (xfs_dir_shortform_t):
      Header: parent(8) + count(1) = 9 bytes
      Entry:  inumber(8) + namelen(1) + name[namelen]
    """
    raw = inode['_raw']
    fork_offset = inode['_data_fork_offset']
    size = inode['di_size']
    data = raw[fork_offset:fork_offset + size]

    if sb is not None and has_dirv2(sb):
        return _read_dir_sf_v2(data, has_ftype(sb))

    if len(data) < XFS_DIR_SF_HDR_SIZE:
        return []

    count = data[8]
    offset = XFS_DIR_SF_HDR_SIZE

    entries = []
    for _ in range(count):
        if offset + 9 > len(data):
            break
        ino = struct.unpack('>Q', data[offset:offset + 8])[0]
        namelen = data[offset + 8]
        if offset + 9 + namelen > len(data):
            break
        name = data[offset + 9:offset + 9 + namelen].decode('ascii', errors='replace')
        offset += 9 + namelen

        if name not in ('.', '..') and ino > 0:
            entries.append((name, ino))

    return entries


def read_dir_sf_parent(inode, sb=None):
    """Read parent inode number from shortform directory header."""
    raw = inode['_raw']
    fork_offset = inode['_data_fork_offset']
    size = inode['di_size']
    data = raw[fork_offset:fork_offset + size]

    if sb is not None and has_dirv2(sb):
        return _read_dir_sf_parent_v2(data)

    if len(data) < 8:
        return None
    return struct.unpack('>Q', data[0:8])[0]


def _read_dir_sf_v2(data, ftype=False):
    """Read dir2 shortform directory entries.

    Dir2 shortform (xfs_dir2_sf_t):
      Header: count(1) + i8count(1) + parent(4 or 8)
        - If i8count == 0: parent is 4 bytes (all inos fit in 32-bit)
        - If i8count != 0: parent is 8 bytes, i8count is the real entry count
      Entry: namelen(1) + offset(2) + name[namelen] [+ ftype(1)] + ino(4 or 8)
      '.' and '..' are NOT stored as entries (implicit).
    """
    if len(data) < XFS_DIR2_SF_HDR_SIZE_4:
        return []

    count = data[0]
    i8count = data[1]
    use_8byte = (i8count != 0)

    if use_8byte:
        hdr_size = XFS_DIR2_SF_HDR_SIZE_8
        real_count = i8count
    else:
        hdr_size = XFS_DIR2_SF_HDR_SIZE_4
        real_count = count

    if len(data) < hdr_size:
        return []

    ino_size = 8 if use_8byte else 4
    ftype_size = 1 if ftype else 0
    offset = hdr_size
    entries = []

    for _ in range(real_count):
        if offset + 3 > len(data):
            break
        namelen = data[offset]
        # offset field at offset+1..offset+2 (unused for reading, just skip)
        if offset + 3 + namelen + ftype_size + ino_size > len(data):
            break
        name = data[offset + 3:offset + 3 + namelen].decode('ascii', errors='replace')
        ino_off = offset + 3 + namelen + ftype_size
        if use_8byte:
            ino = struct.unpack('>Q', data[ino_off:ino_off + 8])[0]
        else:
            ino = struct.unpack('>I', data[ino_off:ino_off + 4])[0]
        offset = ino_off + ino_size

        if ino > 0:
            entries.append((name, ino))

    return entries


def _read_dir_sf_parent_v2(data):
    """Read parent inode from dir2 shortform header."""
    if len(data) < XFS_DIR2_SF_HDR_SIZE_4:
        return None

    i8count = data[1]
    if i8count != 0:
        if len(data) < XFS_DIR2_SF_HDR_SIZE_8:
            return None
        return struct.unpack('>Q', data[2:10])[0]
    else:
        return struct.unpack('>I', data[2:6])[0]


def _read_dir_block(f, part_offset, sb, inode):
    """Read block/data format directory entries."""
    blocksize = sb['sb_blocksize']
    dirblklog = sb['sb_dirblklog']

    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return []

    entries = []

    for startoff, startblock, blockcount in extents:
        for blk_idx in range(blockcount):
            disk_off = fsblock_to_offset(sb, part_offset, startblock + blk_idx)
            f.seek(disk_off)
            block_data = f.read(blocksize)
            if len(block_data) < 16:
                continue

            magic4 = struct.unpack('>I', block_data[0:4])[0]
            magic2 = struct.unpack('>H', block_data[8:10])[0]

            if magic2 == XFS_DIR_LEAF_MAGIC:
                _parse_dir_v1_leaf(block_data, entries)
                continue

            if magic4 not in (XFS_DIR2_BLOCK_MAGIC, XFS_DIR2_DATA_MAGIC):
                continue

            # For multi-fsblock dir blocks, read the full dir block
            if dirblklog > 0 and blk_idx % (1 << dirblklog) == 0:
                remaining = min(blockcount - blk_idx, 1 << dirblklog) - 1
                for extra in range(remaining):
                    extra_off = fsblock_to_offset(
                        sb, part_offset, startblock + blk_idx + 1 + extra)
                    f.seek(extra_off)
                    block_data += f.read(blocksize)

            _parse_dir_data_block(block_data, entries, sb)

    return entries


def _parse_dir_v1_leaf(block_data, entries):
    """Parse old IRIX V1 XFS leaf directory block (magic=0xfeeb).

    Header (32 bytes):
      da_blkinfo(12) + count(2) + namebytes(2) + firstused(2) + holes(1) + pad(1) + freemap(12)
    Entry (8 bytes each):
      hashval(4) + nameidx(2) + namelength(1) + pad(1)
    Name at nameidx: inum(8) + name[namelength]
    """
    if len(block_data) < XFS_DIR_LEAF_HDR_SIZE:
        return
    count = struct.unpack('>H', block_data[12:14])[0]
    if count == 0 or count > 512:
        return
    for i in range(count):
        off = XFS_DIR_LEAF_HDR_SIZE + i * XFS_DIR_LEAF_ENTRY_SIZE
        if off + 8 > len(block_data):
            break
        nameidx = struct.unpack('>H', block_data[off + 4:off + 6])[0]
        namelength = block_data[off + 6]
        if namelength == 0:
            continue
        if nameidx + 8 + namelength > len(block_data):
            continue
        inum = struct.unpack('>Q', block_data[nameidx:nameidx + 8])[0]
        name = block_data[nameidx + 8:nameidx + 8 + namelength].decode(
            'ascii', errors='replace')
        if name not in ('.', '..') and inum > 0:
            entries.append((name, inum))


def _parse_dir_data_block(block_data, entries, sb):
    """Parse dir2 data/block format directory entries."""
    magic = struct.unpack('>I', block_data[0:4])[0]

    data_start = XFS_DIR2_DATA_HDR_SIZE
    blocksize = sb['sb_blocksize']
    dirblklog = sb['sb_dirblklog']
    dirblksize = blocksize << dirblklog
    ftype_size = 1 if has_ftype(sb) else 0

    if magic == XFS_DIR2_BLOCK_MAGIC:
        tail_off = dirblksize - XFS_DIR2_BLOCK_TAIL_SIZE
        if tail_off > len(block_data):
            tail_off = len(block_data) - XFS_DIR2_BLOCK_TAIL_SIZE
        if tail_off >= 8:
            leaf_count, stale_count = struct.unpack(
                '>II', block_data[tail_off:tail_off + 8])
            endptr = tail_off - leaf_count * 8
        else:
            endptr = len(block_data)
    else:
        endptr = len(block_data)

    ptr = data_start
    while ptr < endptr:
        if ptr + 2 > len(block_data):
            break

        freetag = struct.unpack('>H', block_data[ptr:ptr + 2])[0]
        if freetag == XFS_DIR2_FREE_TAG:
            if ptr + 4 > len(block_data):
                break
            free_length = struct.unpack('>H', block_data[ptr + 2:ptr + 4])[0]
            if free_length == 0:
                break
            ptr += free_length
            continue

        if ptr + 9 > len(block_data):
            break

        inumber = struct.unpack('>Q', block_data[ptr:ptr + 8])[0]
        namelen = block_data[ptr + 8]

        if ptr + 9 + namelen + ftype_size + 2 > len(block_data):
            break

        name = block_data[ptr + 9:ptr + 9 + namelen].decode(
            'ascii', errors='replace')

        entry_size = (8 + 1 + namelen + ftype_size + 2 + 7) & ~7
        ptr += entry_size

        if name not in ('.', '..'):
            entries.append((name, inumber))


# ── Write Operations: V1 Shortform ─────────────────────────────────

def add_entry_sf(inode, sb, name, child_ino):
    """Add an entry to a shortform directory.

    Returns True if entry was added, False if no room (need conversion).
    Modifies inode in place. Dispatches to V1 or dir2.
    """
    if has_dirv2(sb):
        return _add_entry_sf_v2(inode, sb, name, child_ino)

    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    inodesize = sb['sb_inodesize']

    if inode['di_forkoff']:
        dfork_size = inode['di_forkoff'] * 8
    else:
        dfork_size = inodesize - fork_offset

    old_size = inode['di_size']
    entry_size = 8 + 1 + len(name_bytes)  # ino(8) + namelen(1) + name
    new_size = old_size + entry_size

    if new_size > dfork_size:
        return False  # won't fit

    # Append entry at the end of current data
    off = fork_offset + old_size
    struct.pack_into('>Q', raw, off, child_ino)
    raw[off + 8] = len(name_bytes)
    raw[off + 9:off + 9 + len(name_bytes)] = name_bytes

    # Update count in header
    raw[fork_offset + 8] += 1

    inode['_raw'] = bytes(raw)
    inode['di_size'] = new_size

    return True


def remove_entry_sf(inode, sb, name):
    """Remove an entry from a shortform directory.

    Returns True if entry was found and removed, False otherwise.
    Modifies inode in place. Dispatches to V1 or dir2.
    """
    if has_dirv2(sb):
        return _remove_entry_sf_v2(inode, sb, name)

    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    size = inode['di_size']
    data = bytes(raw[fork_offset:fork_offset + size])

    if len(data) < XFS_DIR_SF_HDR_SIZE:
        return False

    count = data[8]
    offset = XFS_DIR_SF_HDR_SIZE

    for i in range(count):
        if offset + 9 > len(data):
            break
        namelen = data[offset + 8]
        if offset + 9 + namelen > len(data):
            break
        entry_name = data[offset + 9:offset + 9 + namelen]
        entry_size = 9 + namelen

        if entry_name == name_bytes:
            # Found — remove by shifting remaining data left
            new_data = bytearray(data)
            new_data[offset:offset + entry_size] = b''
            # Decrement count
            new_data[8] -= 1
            new_size = len(new_data)

            # Write back to raw
            raw[fork_offset:fork_offset + size] = b'\x00' * size
            raw[fork_offset:fork_offset + new_size] = new_data
            inode['_raw'] = bytes(raw)
            inode['di_size'] = new_size
            return True

        offset += entry_size

    return False


def init_dir_sf(inode, sb, parent_ino):
    """Initialize a shortform directory with no entries.

    Dispatches to V1 or dir2 based on superblock version.
    """
    if has_dirv2(sb):
        return _init_dir_sf_v2(inode, sb, parent_ino)

    # V1: 9-byte header: parent(8) + count(0)
    header = struct.pack('>Q', parent_ino) + b'\x00'  # count=0
    set_data_fork(inode, sb, header)
    inode['di_format'] = XFS_DINODE_FMT_LOCAL
    inode['di_size'] = XFS_DIR_SF_HDR_SIZE
    inode['di_nextents'] = 0
    inode['di_nblocks'] = 0


# ── Write Operations: Dir2 Shortform ──────────────────────────────

def _init_dir_sf_v2(inode, sb, parent_ino):
    """Initialize a dir2 shortform directory with no entries.

    Uses 4-byte parent if it fits, otherwise 8-byte.
    """
    if parent_ino <= XFS_DIR2_MAX_SHORT_INUM:
        header = struct.pack('>BBi', 0, 0, 0)[:2] + struct.pack('>I', parent_ino)
        hdr_size = XFS_DIR2_SF_HDR_SIZE_4
    else:
        header = struct.pack('>BB', 0, 0) + struct.pack('>Q', parent_ino)
        hdr_size = XFS_DIR2_SF_HDR_SIZE_8
    set_data_fork(inode, sb, header)
    inode['di_format'] = XFS_DINODE_FMT_LOCAL
    inode['di_size'] = hdr_size
    inode['di_nextents'] = 0
    inode['di_nblocks'] = 0


def _add_entry_sf_v2(inode, sb, name, child_ino):
    """Add an entry to a dir2 shortform directory.

    Dir2 SF entry: namelen(1) + offset(2) + name[namelen] [+ ftype(1)] + ino(4 or 8)
    Returns True if added, False if no room.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    inodesize = sb['sb_inodesize']
    ftype_on = has_ftype(sb)
    ftype_size = 1 if ftype_on else 0

    if inode['di_forkoff']:
        dfork_size = inode['di_forkoff'] * 8
    else:
        dfork_size = inodesize - fork_offset

    old_size = inode['di_size']
    data = bytes(raw[fork_offset:fork_offset + old_size])

    if len(data) < XFS_DIR2_SF_HDR_SIZE_4:
        return False

    count = data[0]
    i8count = data[1]
    use_8byte = (i8count != 0)

    # Check if we need to upgrade to 8-byte inodes
    if not use_8byte and child_ino > XFS_DIR2_MAX_SHORT_INUM:
        return _add_entry_sf_v2_upgrade_ino(inode, sb, name_bytes, child_ino)

    ino_size = 8 if use_8byte else 4
    entry_size = 1 + 2 + len(name_bytes) + ftype_size + ino_size
    new_size = old_size + entry_size

    if new_size > dfork_size:
        return False  # won't fit

    # Compute next virtual data-block offset
    next_offset = _sf_v2_next_offset(data, i8count if use_8byte else count,
                                     use_8byte, ftype_on)

    # Append entry at end of current data
    off = fork_offset + old_size
    raw[off] = len(name_bytes)
    struct.pack_into('>H', raw, off + 1, next_offset)
    raw[off + 3:off + 3 + len(name_bytes)] = name_bytes
    ftype_off = off + 3 + len(name_bytes)
    if ftype_on:
        raw[ftype_off] = XFS_DIR3_FT_UNKNOWN  # we don't know type at add time
        ino_off = ftype_off + 1
    else:
        ino_off = ftype_off
    if use_8byte:
        struct.pack_into('>Q', raw, ino_off, child_ino)
    else:
        struct.pack_into('>I', raw, ino_off, child_ino)

    # Update counts in header
    if use_8byte:
        raw[fork_offset + 1] = i8count + 1  # i8count
        raw[fork_offset] = 0                 # count stays 0 when using i8count
    else:
        raw[fork_offset] = count + 1
        raw[fork_offset + 1] = 0

    inode['_raw'] = bytes(raw)
    inode['di_size'] = new_size

    return True


def _sf_v2_next_offset(data, entry_count, use_8byte, ftype_on=False):
    """Compute the next virtual data-block offset for a dir2 SF entry.

    Walks existing entries to find where the next virtual offset would be.
    """
    if entry_count == 0:
        return XFS_DIR2_DATA_FIRST_OFFSET

    hdr_size = XFS_DIR2_SF_HDR_SIZE_8 if use_8byte else XFS_DIR2_SF_HDR_SIZE_4
    ino_size = 8 if use_8byte else 4
    ftype_size = 1 if ftype_on else 0
    offset = hdr_size

    last_offset = XFS_DIR2_DATA_FIRST_OFFSET
    last_entry_size = 0

    for _ in range(entry_count):
        if offset + 3 > len(data):
            break
        namelen = data[offset]
        entry_voffset = struct.unpack('>H', data[offset + 1:offset + 3])[0]
        entry_total = 1 + 2 + namelen + ftype_size + ino_size
        offset += entry_total

        # Track the last (highest) offset entry
        if entry_voffset >= last_offset:
            last_offset = entry_voffset
            # Dir2 data entry size: ino(8) + namelen(1) + name [+ ftype(1)] + tag(2), 8-byte aligned
            last_entry_size = (8 + 1 + namelen + ftype_size + 2 + 7) & ~7

    return last_offset + last_entry_size


def _add_entry_sf_v2_upgrade_ino(inode, sb, name_bytes, child_ino):
    """Handle 4->8 byte inode upgrade when new ino > 0xFFFFFFFF.

    Rewrites all existing entries from 4-byte to 8-byte inodes, then adds
    the new entry. Returns True on success, False if no room.
    """
    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    inodesize = sb['sb_inodesize']
    ftype_on = has_ftype(sb)
    ftype_size = 1 if ftype_on else 0

    if inode['di_forkoff']:
        dfork_size = inode['di_forkoff'] * 8
    else:
        dfork_size = inodesize - fork_offset

    old_size = inode['di_size']
    data = bytes(raw[fork_offset:fork_offset + old_size])

    count = data[0]
    # Read parent (currently 4-byte)
    parent_ino = struct.unpack('>I', data[2:6])[0]

    # Parse existing 4-byte entries
    entries = []
    offset = XFS_DIR2_SF_HDR_SIZE_4
    for _ in range(count):
        if offset + 3 > len(data):
            break
        namelen = data[offset]
        voffset = struct.unpack('>H', data[offset + 1:offset + 3])[0]
        ename = data[offset + 3:offset + 3 + namelen]
        ft_val = data[offset + 3 + namelen] if ftype_on else 0
        ino_off = offset + 3 + namelen + ftype_size
        eino = struct.unpack('>I', data[ino_off:ino_off + 4])[0]
        entries.append((namelen, voffset, ename, ft_val, eino))
        offset += 1 + 2 + namelen + ftype_size + 4

    # Calculate new size with 8-byte inodes
    new_count = count + 1
    new_hdr_size = XFS_DIR2_SF_HDR_SIZE_8  # parent becomes 8-byte
    new_size = new_hdr_size
    for namelen, voffset, ename, ft_val, eino in entries:
        new_size += 1 + 2 + namelen + ftype_size + 8
    new_size += 1 + 2 + len(name_bytes) + ftype_size + 8  # new entry

    if new_size > dfork_size:
        return False

    # Build new data
    new_data = bytearray(new_size)
    new_data[0] = 0        # count = 0 when using i8count
    new_data[1] = new_count  # i8count
    struct.pack_into('>Q', new_data, 2, parent_ino)

    off = new_hdr_size
    for namelen, voffset, ename, ft_val, eino in entries:
        new_data[off] = namelen
        struct.pack_into('>H', new_data, off + 1, voffset)
        new_data[off + 3:off + 3 + namelen] = ename
        if ftype_on:
            new_data[off + 3 + namelen] = ft_val
        struct.pack_into('>Q', new_data, off + 3 + namelen + ftype_size, eino)
        off += 1 + 2 + namelen + ftype_size + 8

    # Add new entry
    next_offset = _sf_v2_next_offset(bytes(new_data[:off]), count, True, ftype_on)
    new_data[off] = len(name_bytes)
    struct.pack_into('>H', new_data, off + 1, next_offset)
    new_data[off + 3:off + 3 + len(name_bytes)] = name_bytes
    if ftype_on:
        new_data[off + 3 + len(name_bytes)] = XFS_DIR3_FT_UNKNOWN
    struct.pack_into('>Q', new_data, off + 3 + len(name_bytes) + ftype_size, child_ino)

    # Write back
    raw[fork_offset:fork_offset + old_size] = b'\x00' * old_size
    raw[fork_offset:fork_offset + new_size] = new_data
    inode['_raw'] = bytes(raw)
    inode['di_size'] = new_size

    return True


def _remove_entry_sf_v2(inode, sb, name):
    """Remove an entry from a dir2 shortform directory.

    Returns True if found and removed, False otherwise.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    size = inode['di_size']
    data = bytes(raw[fork_offset:fork_offset + size])

    if len(data) < XFS_DIR2_SF_HDR_SIZE_4:
        return False

    count = data[0]
    i8count = data[1]
    use_8byte = (i8count != 0)
    real_count = i8count if use_8byte else count
    hdr_size = XFS_DIR2_SF_HDR_SIZE_8 if use_8byte else XFS_DIR2_SF_HDR_SIZE_4
    ino_size = 8 if use_8byte else 4
    ftype_size = 1 if has_ftype(sb) else 0

    offset = hdr_size

    for i in range(real_count):
        if offset + 3 > len(data):
            break
        namelen = data[offset]
        entry_total = 1 + 2 + namelen + ftype_size + ino_size
        if offset + entry_total > len(data):
            break

        entry_name = data[offset + 3:offset + 3 + namelen]
        if entry_name == name_bytes:
            # Found — remove by shifting remaining data left
            new_data = bytearray(data)
            new_data[offset:offset + entry_total] = b''
            # Decrement count
            if use_8byte:
                new_data[1] = i8count - 1
            else:
                new_data[0] = count - 1
            new_size = len(new_data)

            # Write back to raw
            raw[fork_offset:fork_offset + size] = b'\x00' * size
            raw[fork_offset:fork_offset + new_size] = new_data
            inode['_raw'] = bytes(raw)
            inode['di_size'] = new_size
            return True

        offset += entry_total

    return False


# ── Write Operations: V1 Leaf ──────────────────────────────────────

def add_entry_v1_leaf(f, part_offset, sb, inode, name, child_ino):
    """Add an entry to a V1 leaf directory block.

    Returns True if entry was added, False if block is full.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    blocksize = sb['sb_blocksize']
    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return False

    # Read the leaf block
    startoff, startblock, blockcount = extents[0]
    disk_off = fsblock_to_offset(sb, part_offset, startblock)
    f.seek(disk_off)
    block = bytearray(f.read(blocksize))

    if len(block) < XFS_DIR_LEAF_HDR_SIZE:
        return False

    magic2 = struct.unpack('>H', block[8:10])[0]
    if magic2 != XFS_DIR_LEAF_MAGIC:
        return False

    count = struct.unpack('>H', block[12:14])[0]
    namebytes = struct.unpack('>H', block[14:16])[0]
    firstused = struct.unpack('>H', block[16:18])[0]

    # Name struct size: ino(8) + name bytes
    name_struct_size = 8 + len(name_bytes)

    # Check if there's room
    entries_end = XFS_DIR_LEAF_HDR_SIZE + (count + 1) * XFS_DIR_LEAF_ENTRY_SIZE
    new_firstused = firstused - name_struct_size

    if entries_end > new_firstused:
        return False  # no room

    # Compute hash for this name
    hashval = xfs_da_hashname(name_bytes)

    # Find insertion point (entries are sorted by hashval)
    insert_idx = count
    for i in range(count):
        eoff = XFS_DIR_LEAF_HDR_SIZE + i * XFS_DIR_LEAF_ENTRY_SIZE
        ehash = struct.unpack('>I', block[eoff:eoff + 4])[0]
        if hashval < ehash:
            insert_idx = i
            break
        elif hashval == ehash:
            # Same hash — insert after existing entries with same hash
            insert_idx = i + 1

    # Shift entries after insertion point
    if insert_idx < count:
        src = XFS_DIR_LEAF_HDR_SIZE + insert_idx * XFS_DIR_LEAF_ENTRY_SIZE
        dst = src + XFS_DIR_LEAF_ENTRY_SIZE
        remaining = (count - insert_idx) * XFS_DIR_LEAF_ENTRY_SIZE
        block[dst:dst + remaining] = block[src:src + remaining]

    # Write name struct at new_firstused
    struct.pack_into('>Q', block, new_firstused, child_ino)
    block[new_firstused + 8:new_firstused + 8 + len(name_bytes)] = name_bytes

    # Write entry
    eoff = XFS_DIR_LEAF_HDR_SIZE + insert_idx * XFS_DIR_LEAF_ENTRY_SIZE
    struct.pack_into('>I', block, eoff, hashval)
    struct.pack_into('>H', block, eoff + 4, new_firstused)
    block[eoff + 6] = len(name_bytes)
    block[eoff + 7] = 0  # pad

    # Update header
    struct.pack_into('>H', block, 12, count + 1)
    struct.pack_into('>H', block, 14, namebytes + len(name_bytes))
    struct.pack_into('>H', block, 16, new_firstused)

    # Update freemap[0] (simplistic: just track first free region)
    struct.pack_into('>H', block, 20, entries_end)
    struct.pack_into('>H', block, 22, new_firstused - entries_end)

    # Write block back
    f.seek(disk_off)
    f.write(bytes(block))

    return True


def remove_entry_v1_leaf(f, part_offset, sb, inode, name):
    """Remove an entry from a V1 leaf directory block.

    Returns True if found and removed, False otherwise.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    blocksize = sb['sb_blocksize']
    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return False

    startoff, startblock, blockcount = extents[0]
    disk_off = fsblock_to_offset(sb, part_offset, startblock)
    f.seek(disk_off)
    block = bytearray(f.read(blocksize))

    if len(block) < XFS_DIR_LEAF_HDR_SIZE:
        return False

    magic2 = struct.unpack('>H', block[8:10])[0]
    if magic2 != XFS_DIR_LEAF_MAGIC:
        return False

    count = struct.unpack('>H', block[12:14])[0]

    # Find the entry
    for i in range(count):
        eoff = XFS_DIR_LEAF_HDR_SIZE + i * XFS_DIR_LEAF_ENTRY_SIZE
        nameidx = struct.unpack('>H', block[eoff + 4:eoff + 6])[0]
        namelength = block[eoff + 6]

        if namelength != len(name_bytes):
            continue
        if block[nameidx + 8:nameidx + 8 + namelength] == name_bytes:
            # Found — remove entry from entry table (shift left)
            if i < count - 1:
                src = eoff + XFS_DIR_LEAF_ENTRY_SIZE
                remaining = (count - 1 - i) * XFS_DIR_LEAF_ENTRY_SIZE
                block[eoff:eoff + remaining] = block[src:src + remaining]

            # Zero the last entry slot
            last_off = XFS_DIR_LEAF_HDR_SIZE + (count - 1) * XFS_DIR_LEAF_ENTRY_SIZE
            block[last_off:last_off + XFS_DIR_LEAF_ENTRY_SIZE] = b'\x00' * XFS_DIR_LEAF_ENTRY_SIZE

            # Note: we don't reclaim name space (set holes=1 instead)
            namebytes = struct.unpack('>H', block[14:16])[0]
            struct.pack_into('>H', block, 12, count - 1)
            struct.pack_into('>H', block, 14, namebytes - namelength)
            block[18] = 1  # holes flag

            f.seek(disk_off)
            f.write(bytes(block))
            return True

    return False


# ── Write Operations: Dir2 Block ───────────────────────────────────

def add_entry_dir2_block(f, part_offset, sb, inode, name, child_ino):
    """Add an entry to a dir2 block format directory.

    Returns True if added, False if no space.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    blocksize = sb['sb_blocksize']
    dirblklog = sb['sb_dirblklog']
    dirblksize = blocksize << dirblklog
    ftype_size = 1 if has_ftype(sb) else 0

    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return False

    # Read the dir block
    startoff, startblock, blockcount = extents[0]
    disk_off = fsblock_to_offset(sb, part_offset, startblock)
    f.seek(disk_off)
    block = bytearray(f.read(dirblksize))

    magic = struct.unpack('>I', block[0:4])[0]
    if magic != XFS_DIR2_BLOCK_MAGIC:
        return False

    # Read tail
    tail_off = dirblksize - XFS_DIR2_BLOCK_TAIL_SIZE
    leaf_count, stale_count = struct.unpack('>II', block[tail_off:tail_off + 8])

    # Entry size (8-byte aligned): ino(8) + namelen(1) + name [+ ftype(1)] + tag(2)
    entry_size = (8 + 1 + len(name_bytes) + ftype_size + 2 + 7) & ~7

    # Find free space in data area
    endptr = tail_off - leaf_count * 8
    ptr = XFS_DIR2_DATA_HDR_SIZE
    insert_off = -1

    while ptr < endptr:
        if ptr + 2 > len(block):
            break

        freetag = struct.unpack('>H', block[ptr:ptr + 2])[0]
        if freetag == XFS_DIR2_FREE_TAG:
            if ptr + 4 > len(block):
                break
            free_length = struct.unpack('>H', block[ptr + 2:ptr + 4])[0]
            if free_length == 0:
                break
            if free_length >= entry_size:
                insert_off = ptr
                break
            ptr += free_length
            continue

        # Skip existing entry
        if ptr + 9 > len(block):
            break
        namelen = block[ptr + 8]
        existing_size = (8 + 1 + namelen + ftype_size + 2 + 7) & ~7
        ptr += existing_size

    if insert_off < 0:
        return False  # no space

    # Read the free entry to know its size
    free_length = struct.unpack('>H', block[insert_off + 2:insert_off + 4])[0]

    # Write the data entry: ino(8) + namelen(1) + name [+ ftype(1)] + pad + tag(2)
    struct.pack_into('>Q', block, insert_off, child_ino)
    block[insert_off + 8] = len(name_bytes)
    block[insert_off + 9:insert_off + 9 + len(name_bytes)] = name_bytes
    if ftype_size:
        block[insert_off + 9 + len(name_bytes)] = XFS_DIR3_FT_UNKNOWN
    # Pad with zeros between name/ftype end and tag
    pad_start = insert_off + 9 + len(name_bytes) + ftype_size
    for j in range(pad_start, insert_off + entry_size - 2):
        block[j] = 0
    struct.pack_into('>H', block, insert_off + entry_size - 2, insert_off)

    # If leftover free space, write a new free entry after this one
    leftover = free_length - entry_size
    if leftover >= 16:  # minimum useful free space
        new_free_off = insert_off + entry_size
        struct.pack_into('>H', block, new_free_off, XFS_DIR2_FREE_TAG)
        struct.pack_into('>H', block, new_free_off + 2, leftover)
        # End tag for free entry
        struct.pack_into('>H', block, new_free_off + leftover - 2, new_free_off)
    elif leftover > 0:
        # Too small for a free entry — zero it out
        new_free_off = insert_off + entry_size
        block[new_free_off:new_free_off + leftover] = b'\x00' * leftover

    # Add leaf entry (sorted by hash)
    hashval = xfs_da_hashname(name_bytes)
    addr = insert_off >> 3  # dir2 address (8-byte units)

    # Insert into leaf area (before tail), maintaining hash order
    leaf_start = endptr
    new_leaf_count = leaf_count + 1

    # Read existing leaf entries
    leaves = []
    for i in range(leaf_count):
        loff = leaf_start + i * 8
        lhash = struct.unpack('>I', block[loff:loff + 4])[0]
        laddr = struct.unpack('>I', block[loff + 4:loff + 8])[0]
        leaves.append((lhash, laddr))

    # Insert new leaf in sorted position
    inserted = False
    new_leaves = []
    for lhash, laddr in leaves:
        if not inserted and hashval <= lhash:
            new_leaves.append((hashval, addr))
            inserted = True
        new_leaves.append((lhash, laddr))
    if not inserted:
        new_leaves.append((hashval, addr))

    # Check if new leaf array fits
    new_leaf_start = tail_off - new_leaf_count * 8
    if new_leaf_start < insert_off + entry_size:
        return False  # no room for leaf entries

    # Write leaf entries
    for i, (lhash, laddr) in enumerate(new_leaves):
        loff = new_leaf_start + i * 8
        struct.pack_into('>I', block, loff, lhash)
        struct.pack_into('>I', block, loff + 4, laddr)

    # Clear old leaf area if it shifted
    if new_leaf_start < leaf_start:
        block[new_leaf_start:leaf_start] = b'\x00' * (leaf_start - new_leaf_start)

    # Update tail
    struct.pack_into('>II', block, tail_off, new_leaf_count, 0)

    # Update bestfree in header (simplified: recalculate)
    _update_dir2_bestfree(block, dirblksize, new_leaf_start, ftype_size)

    # Write block back
    f.seek(disk_off)
    f.write(bytes(block))

    return True


def remove_entry_dir2_block(f, part_offset, sb, inode, name):
    """Remove an entry from a dir2 block format directory.

    Returns True if found and removed, False otherwise.
    """
    if isinstance(name, str):
        name_bytes = name.encode('ascii')
    else:
        name_bytes = name

    blocksize = sb['sb_blocksize']
    dirblklog = sb['sb_dirblklog']
    dirblksize = blocksize << dirblklog
    ftype_size = 1 if has_ftype(sb) else 0

    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return False

    startoff, startblock, blockcount = extents[0]
    disk_off = fsblock_to_offset(sb, part_offset, startblock)
    f.seek(disk_off)
    block = bytearray(f.read(dirblksize))

    magic = struct.unpack('>I', block[0:4])[0]
    if magic != XFS_DIR2_BLOCK_MAGIC:
        return False

    tail_off = dirblksize - XFS_DIR2_BLOCK_TAIL_SIZE
    leaf_count, stale_count = struct.unpack('>II', block[tail_off:tail_off + 8])
    leaf_start = tail_off - leaf_count * 8

    # Find the entry in data area
    ptr = XFS_DIR2_DATA_HDR_SIZE
    found_off = -1
    found_size = 0

    while ptr < leaf_start:
        if ptr + 2 > len(block):
            break

        freetag = struct.unpack('>H', block[ptr:ptr + 2])[0]
        if freetag == XFS_DIR2_FREE_TAG:
            if ptr + 4 > len(block):
                break
            free_length = struct.unpack('>H', block[ptr + 2:ptr + 4])[0]
            if free_length == 0:
                break
            ptr += free_length
            continue

        if ptr + 9 > len(block):
            break

        namelen = block[ptr + 8]
        entry_size = (8 + 1 + namelen + ftype_size + 2 + 7) & ~7

        if namelen == len(name_bytes):
            entry_name = block[ptr + 9:ptr + 9 + namelen]
            if entry_name == name_bytes:
                found_off = ptr
                found_size = entry_size
                break

        ptr += entry_size

    if found_off < 0:
        return False

    # Convert entry to free space
    struct.pack_into('>H', block, found_off, XFS_DIR2_FREE_TAG)
    struct.pack_into('>H', block, found_off + 2, found_size)
    # Zero the rest of the entry
    block[found_off + 4:found_off + found_size - 2] = b'\x00' * (found_size - 6)
    # End tag
    struct.pack_into('>H', block, found_off + found_size - 2, found_off)

    # Mark the leaf entry as stale (set address to XFS_DIR2_NULL_DATAPTR = 0xFFFFFFFF)
    addr = found_off >> 3
    new_stale = stale_count
    for i in range(leaf_count):
        loff = leaf_start + i * 8
        laddr = struct.unpack('>I', block[loff + 4:loff + 8])[0]
        if laddr == addr:
            struct.pack_into('>I', block, loff + 4, 0xFFFFFFFF)
            new_stale += 1
            break

    # Update tail stale count
    struct.pack_into('>II', block, tail_off, leaf_count, new_stale)

    # Update bestfree
    _update_dir2_bestfree(block, dirblksize, leaf_start, ftype_size)

    f.seek(disk_off)
    f.write(bytes(block))

    return True


def _update_dir2_bestfree(block, dirblksize, data_endptr, ftype_size=0):
    """Recalculate the 3 bestfree entries in a dir2 data/block header.

    Scans for free space entries and records the 3 largest.
    """
    # Header: magic(4) + bestfree[3] (each: offset(2) + length(2)) = 16 bytes
    free_list = []

    ptr = XFS_DIR2_DATA_HDR_SIZE
    while ptr < data_endptr:
        if ptr + 2 > len(block):
            break
        freetag = struct.unpack('>H', block[ptr:ptr + 2])[0]
        if freetag == XFS_DIR2_FREE_TAG:
            if ptr + 4 > len(block):
                break
            free_length = struct.unpack('>H', block[ptr + 2:ptr + 4])[0]
            if free_length == 0:
                break
            free_list.append((free_length, ptr))
            ptr += free_length
        else:
            if ptr + 9 > len(block):
                break
            namelen = block[ptr + 8]
            entry_size = (8 + 1 + namelen + ftype_size + 2 + 7) & ~7
            ptr += entry_size

    # Sort by size descending, take top 3
    free_list.sort(key=lambda x: x[0], reverse=True)

    for i in range(3):
        off = 4 + i * 4  # bestfree[i] in header
        if i < len(free_list):
            length, foff = free_list[i]
            struct.pack_into('>HH', block, off, foff, length)
        else:
            struct.pack_into('>HH', block, off, 0, 0)


# ── Shortform to Block Conversion ──────────────────────────────────

def sf_to_v1_leaf(f, part_offset, sb, inode, ino, parent_ino, alloc_fn):
    """Convert a shortform directory to a V1 leaf directory block.

    Called when shortform can't hold any more entries.
    alloc_fn(f, part_offset, sb, count) -> list of (fsblock, count) tuples.

    Returns True on success.
    """
    blocksize = sb['sb_blocksize']

    # Read current shortform entries
    entries = read_dir_sf(inode)

    # Allocate one block
    allocations = alloc_fn(f, part_offset, sb, 1)
    if not allocations:
        return False
    fsblock, count = allocations[0]

    # Build V1 leaf block
    block = bytearray(blocksize)

    # da_blkinfo: forw(4)=0, back(4)=0, magic(2)=0xfeeb, pad(2)=0
    struct.pack_into('>IIH', block, 0, 0, 0, XFS_DIR_LEAF_MAGIC)

    # Add . and .. entries first, then all existing entries
    all_entries = [('.', ino), ('..', parent_ino)] + entries

    entry_count = len(all_entries)
    firstused = blocksize
    namebytes_total = 0

    # Sort entries by hash for the entry table
    hashed_entries = []
    for name, entry_ino in all_entries:
        name_bytes = name.encode('ascii') if isinstance(name, str) else name
        hashval = xfs_da_hashname(name_bytes)
        hashed_entries.append((hashval, name_bytes, entry_ino))
    hashed_entries.sort(key=lambda x: x[0])

    # Place name structs from end of block, entries from offset 32
    for i, (hashval, name_bytes, entry_ino) in enumerate(hashed_entries):
        name_struct_size = 8 + len(name_bytes)
        firstused -= name_struct_size
        namebytes_total += len(name_bytes)

        # Write name struct
        struct.pack_into('>Q', block, firstused, entry_ino)
        block[firstused + 8:firstused + 8 + len(name_bytes)] = name_bytes

        # Write entry
        eoff = XFS_DIR_LEAF_HDR_SIZE + i * XFS_DIR_LEAF_ENTRY_SIZE
        struct.pack_into('>I', block, eoff, hashval)
        struct.pack_into('>H', block, eoff + 4, firstused)
        block[eoff + 6] = len(name_bytes)
        block[eoff + 7] = 0  # pad

    # Update header
    entries_end = XFS_DIR_LEAF_HDR_SIZE + entry_count * XFS_DIR_LEAF_ENTRY_SIZE
    struct.pack_into('>H', block, 12, entry_count)
    struct.pack_into('>H', block, 14, namebytes_total)
    struct.pack_into('>H', block, 16, firstused)
    block[18] = 0  # holes
    block[19] = 0  # pad

    # Freemap[0]: free region between entries and names
    struct.pack_into('>HH', block, 20, entries_end, firstused - entries_end)
    # Freemap[1] and [2]: empty
    struct.pack_into('>HH', block, 24, 0, 0)
    struct.pack_into('>HH', block, 28, 0, 0)

    # Write block to disk
    disk_off = fsblock_to_offset(sb, part_offset, fsblock)
    f.seek(disk_off)
    f.write(bytes(block))

    # Update inode to point to the block
    from pyirix.xfs.inode import set_extents
    set_extents(inode, sb, [(0, fsblock, 1)])
    inode['di_size'] = blocksize

    return True


def sf_to_dir2_block(f, part_offset, sb, inode, ino, parent_ino, alloc_fn):
    """Convert a dir2 shortform directory to a dir2 block (XD2B) directory.

    Called when dir2 shortform can't hold any more entries.
    alloc_fn(f, part_offset, sb, count) -> list of (fsblock, count) tuples.

    Layout of XD2B block:
      1. Data header (16 bytes, magic=XD2B, 3 bestfree entries)
      2. "." entry (self ino)
      3. ".." entry (parent ino)
      4. All existing SF entries
      5. Free space entry covering remainder
      6. Leaf entries sorted by hashval
      7. Block tail (leaf_count, stale=0) at end

    Returns True on success.
    """
    blocksize = sb['sb_blocksize']
    dirblklog = sb['sb_dirblklog']
    dirblksize = blocksize << dirblklog
    ftype_on = has_ftype(sb)
    ftype_size = 1 if ftype_on else 0

    # Read current shortform entries
    entries = read_dir_sf(inode, sb)

    # Allocate dir blocks (1 << dirblklog fsblocks)
    nblocks = 1 << dirblklog
    allocations = alloc_fn(f, part_offset, sb, nblocks)
    if not allocations:
        return False
    first_fsblock, alloc_count = allocations[0]

    # Build XD2B block
    block = bytearray(dirblksize)

    # Data header: magic(4) + 3 bestfree entries (each offset(2)+length(2))
    struct.pack_into('>I', block, 0, XFS_DIR2_BLOCK_MAGIC)
    # bestfree filled in later

    ptr = XFS_DIR2_DATA_HDR_SIZE  # 16

    # "." entry: ino(8) + namelen(1)=1 + name(1)="." [+ ftype(1)] + tag(2), 8-byte aligned
    dot_off = ptr
    struct.pack_into('>Q', block, ptr, ino)
    block[ptr + 8] = 1  # namelen
    block[ptr + 9] = ord('.')
    if ftype_on:
        block[ptr + 10] = XFS_DIR3_FT_DIR
    dot_entry_size = (8 + 1 + 1 + ftype_size + 2 + 7) & ~7  # 16 either way
    struct.pack_into('>H', block, ptr + dot_entry_size - 2, dot_off)
    ptr += dot_entry_size

    # ".." entry
    dotdot_off = ptr
    struct.pack_into('>Q', block, ptr, parent_ino)
    block[ptr + 8] = 2  # namelen
    block[ptr + 9] = ord('.')
    block[ptr + 10] = ord('.')
    if ftype_on:
        block[ptr + 11] = XFS_DIR3_FT_DIR
    dotdot_entry_size = (8 + 1 + 2 + ftype_size + 2 + 7) & ~7  # 16 either way
    struct.pack_into('>H', block, ptr + dotdot_entry_size - 2, dotdot_off)
    ptr += dotdot_entry_size

    # All existing shortform entries
    leaf_entries = []

    # Add . and .. to leaf entries
    leaf_entries.append((xfs_da_hashname(b'.'), dot_off >> 3))
    leaf_entries.append((xfs_da_hashname(b'..'), dotdot_off >> 3))

    for name, entry_ino in entries:
        name_bytes = name.encode('ascii') if isinstance(name, str) else name
        entry_off = ptr
        struct.pack_into('>Q', block, ptr, entry_ino)
        block[ptr + 8] = len(name_bytes)
        block[ptr + 9:ptr + 9 + len(name_bytes)] = name_bytes
        if ftype_on:
            block[ptr + 9 + len(name_bytes)] = XFS_DIR3_FT_UNKNOWN
        entry_size = (8 + 1 + len(name_bytes) + ftype_size + 2 + 7) & ~7
        struct.pack_into('>H', block, ptr + entry_size - 2, entry_off)
        ptr += entry_size

        hashval = xfs_da_hashname(name_bytes)
        leaf_entries.append((hashval, entry_off >> 3))

    # Sort leaf entries by hash
    leaf_entries.sort(key=lambda x: x[0])
    leaf_count = len(leaf_entries)

    # Block tail at very end
    tail_off = dirblksize - XFS_DIR2_BLOCK_TAIL_SIZE

    # Leaf entries just before tail
    leaf_start = tail_off - leaf_count * XFS_DIR2_LEAF_ENTRY_SIZE
    for i, (lhash, laddr) in enumerate(leaf_entries):
        loff = leaf_start + i * XFS_DIR2_LEAF_ENTRY_SIZE
        struct.pack_into('>I', block, loff, lhash)
        struct.pack_into('>I', block, loff + 4, laddr)

    # Write tail
    struct.pack_into('>II', block, tail_off, leaf_count, 0)

    # Free space between data entries and leaf area
    free_start = ptr
    free_length = leaf_start - ptr
    if free_length >= 16:
        struct.pack_into('>H', block, free_start, XFS_DIR2_FREE_TAG)
        struct.pack_into('>H', block, free_start + 2, free_length)
        struct.pack_into('>H', block, free_start + free_length - 2, free_start)

    # Update bestfree in header
    _update_dir2_bestfree(block, dirblksize, leaf_start, ftype_size)

    # Write block to disk
    disk_off = fsblock_to_offset(sb, part_offset, first_fsblock)
    f.seek(disk_off)
    f.write(bytes(block))

    # Update inode to point to the block(s)
    from pyirix.xfs.inode import set_extents
    set_extents(inode, sb, [(0, first_fsblock, nblocks)])
    inode['di_size'] = dirblksize

    return True
