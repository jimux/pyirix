"""XFS inode read/write, extent fork management.

Migrated from sgi_mcp/sgi_fs.py lines 508-768.
"""

import struct
import time

from pyirix.xfs.constants import (
    XFS_DINODE_MAGIC, XFS_DATA_FORK_OFFSET, XFS_BMAP_MAGIC,
    XFS_DINODE_FMT_DEV, XFS_DINODE_FMT_LOCAL,
    XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE,
    S_IFMT, S_IFLNK, S_IFDIR, S_IFREG,
    XFSCorruptionError,
)
from pyirix.xfs.ondisk import (
    parse_inode_core, pack_inode_core,
    parse_bmbt_rec, pack_bmbt_rec,
    ino_to_offset, fsblock_to_offset, valid_fsblock,
    NULLFSBLOCK,
)


def read_inode(f, part_offset, sb, ino):
    """Read an XFS inode from disk.

    Returns dict with core fields plus '_raw', '_data_fork_offset',
    or None if magic doesn't match.
    """
    offset = ino_to_offset(sb, ino, part_offset)
    inodesize = sb['sb_inodesize']

    f.seek(offset)
    data = f.read(inodesize)
    if len(data) < 96:
        return None

    magic = struct.unpack('>H', data[0:2])[0]
    if magic != XFS_DINODE_MAGIC:
        return None

    core = parse_inode_core(data)
    if core is None:
        return None

    core['_data_fork_offset'] = XFS_DATA_FORK_OFFSET
    core['_raw'] = data
    return core


def write_inode(f, part_offset, sb, ino, inode):
    """Write an XFS inode back to disk.

    Reconstructs the full inode from core fields + fork data in _raw.
    """
    offset = ino_to_offset(sb, ino, part_offset)
    inodesize = sb['sb_inodesize']

    # Build from _raw if available, else construct fresh
    raw = bytearray(inode.get('_raw', b'\x00' * inodesize))
    if len(raw) < inodesize:
        raw.extend(b'\x00' * (inodesize - len(raw)))

    # Pack core into the first 96 bytes
    core_bytes = pack_inode_core(inode)
    raw[0:96] = core_bytes

    f.seek(offset)
    f.write(bytes(raw[:inodesize]))
    f.flush()


def init_inode(sb, mode, uid=0, gid=0, nlink=1):
    """Create a fresh inode dict with default values.

    Returns inode dict ready for write_inode.
    """
    now = int(time.time())
    inodesize = sb['sb_inodesize']

    inode = {
        'di_magic': XFS_DINODE_MAGIC,
        'di_mode': mode,
        # v2 inodes (32-bit nlink) are only legal when the superblock advertises
        # XFS_SB_VERSION_NLINKBIT (0x20); otherwise use v1 (nlink in di_onlink).
        'di_version': 2 if (sb['sb_versionnum'] & 0x20) else 1,
        'di_format': XFS_DINODE_FMT_LOCAL,
        'di_onlink': nlink if nlink <= 0xFFFF else 0,
        'di_uid': uid,
        'di_gid': gid,
        'di_nlink': nlink,
        'di_projid': 0,
        '_pad': b'\x00' * 10,
        'di_atime_sec': now,
        'di_atime_nsec': 0,
        'di_mtime_sec': now,
        'di_mtime_nsec': 0,
        'di_ctime_sec': now,
        'di_ctime_nsec': 0,
        'di_size': 0,
        'di_nblocks': 0,
        'di_extsize': 0,
        'di_nextents': 0,
        'di_anextents': 0,
        'di_forkoff': 0,
        'di_aformat': 0,
        'di_dmevmask': 0,
        'di_dmstate': 0,
        'di_flags': 0,
        'di_gen': 0,
        '_data_fork_offset': XFS_DATA_FORK_OFFSET,
        '_raw': b'\x00' * inodesize,
    }

    # Write core and next_unlinked into _raw
    raw = bytearray(inodesize)
    raw[0:96] = pack_inode_core(inode)
    # di_next_unlinked = NULLAGBLOCK
    struct.pack_into('>I', raw, 96, 0xFFFFFFFF)
    inode['_raw'] = bytes(raw)

    return inode


def get_data_fork(inode, sb):
    """Get the data fork bytes from an inode.

    Returns (fork_data, dfork_size).
    """
    raw = inode['_raw']
    fork_offset = inode['_data_fork_offset']
    inodesize = sb['sb_inodesize']

    if inode['di_forkoff']:
        dfork_size = inode['di_forkoff'] * 8
    else:
        dfork_size = inodesize - fork_offset

    fork_data = raw[fork_offset:fork_offset + dfork_size]
    return fork_data, dfork_size


def set_data_fork(inode, sb, fork_data):
    """Set the data fork bytes in an inode.

    Updates _raw in place. fork_data must fit in the available space.
    """
    raw = bytearray(inode['_raw'])
    fork_offset = inode['_data_fork_offset']
    inodesize = sb['sb_inodesize']

    if inode['di_forkoff']:
        dfork_size = inode['di_forkoff'] * 8
    else:
        dfork_size = inodesize - fork_offset

    if len(fork_data) > dfork_size:
        raise XFSCorruptionError(
            f"Fork data ({len(fork_data)}) exceeds available space ({dfork_size})")

    # Zero the fork area first, then write new data
    raw[fork_offset:fork_offset + dfork_size] = b'\x00' * dfork_size
    raw[fork_offset:fork_offset + len(fork_data)] = fork_data
    inode['_raw'] = bytes(raw)


def get_extents(f, part_offset, sb, inode):
    """Get extent list for an XFS inode.

    Returns list of (startoff, startblock, blockcount) tuples.
    """
    fmt = inode['di_format']
    fork_data, dfork_size = get_data_fork(inode, sb)

    if fmt == XFS_DINODE_FMT_EXTENTS:
        nextents = inode['di_nextents']
        extents = []
        for i in range(nextents):
            rec_off = i * 16
            if rec_off + 16 > len(fork_data):
                break
            startoff, startblock, blockcount, flag = parse_bmbt_rec(
                fork_data[rec_off:rec_off + 16])
            if blockcount > 0:
                extents.append((startoff, startblock, blockcount))
        return extents

    elif fmt == XFS_DINODE_FMT_BTREE:
        return _btree_get_extents(f, part_offset, sb, fork_data)

    return []


def set_extents(inode, sb, extents):
    """Set the extent list in an inode's data fork (FMT_EXTENTS only).

    extents: list of (startoff, startblock, blockcount) tuples.
    Updates inode format, nextents, nblocks, and fork data.
    """
    fork_data, dfork_size = get_data_fork(inode, sb)

    # Check if extents fit inline
    needed = len(extents) * 16
    if needed > dfork_size:
        raise XFSCorruptionError(
            f"Too many extents ({len(extents)}) for inline fork ({dfork_size} bytes)")

    # Build extent records
    rec_data = bytearray()
    total_blocks = 0
    for startoff, startblock, blockcount in extents:
        rec_data.extend(pack_bmbt_rec(startoff, startblock, blockcount))
        total_blocks += blockcount

    inode['di_format'] = XFS_DINODE_FMT_EXTENTS
    inode['di_nextents'] = len(extents)
    inode['di_nblocks'] = total_blocks

    set_data_fork(inode, sb, bytes(rec_data))


def read_file_data(f, part_offset, sb, inode):
    """Read file data from an XFS inode. Returns bytes."""
    size = inode['di_size']
    if size <= 0:
        return b''

    fmt = inode['di_format']

    if fmt == XFS_DINODE_FMT_LOCAL:
        fork_offset = inode['_data_fork_offset']
        raw = inode['_raw']
        return raw[fork_offset:fork_offset + size]

    extents = get_extents(f, part_offset, sb, inode)
    if not extents:
        return b''

    blocksize = sb['sb_blocksize']
    # Place each extent at its LOGICAL offset (startoff * blocksize), zero-filling
    # any holes. A sparse file (di_nblocks < ceil(di_size/blocksize)) has a gap
    # between extents; concatenating extents contiguously — ignoring startoff —
    # shifts all post-hole data backward and truncates the tail, silently
    # corrupting the file (e.g. libm.so dropped its section-header tail). Build a
    # size-sized zero buffer and drop each extent at its true position.
    result = bytearray(size)
    for startoff, startblock, blockcount in extents:
        disk_off = fsblock_to_offset(sb, part_offset, startblock)
        f.seek(disk_off)
        data = f.read(blockcount * blocksize)
        pos = startoff * blocksize
        if pos >= size:
            continue
        end = min(pos + len(data), size)
        result[pos:end] = data[:end - pos]

    return bytes(result)


def write_file_data(f, part_offset, sb, inode, ino, data, alloc_fn):
    """Write file data to an XFS inode — ALWAYS as extents.

    IRIX 6.5 XFS V1 does not support FMT_LOCAL (inline) data forks for
    regular files: the kernel flags such inodes as
    "corrupt inode (local format for regular file)" and fails the read.
    (Inline is only legal for directories' short form and symlinks.)
    So even one-byte files get a full data block.

    alloc_fn(f, part_offset, sb, count) -> list of (fsblock, count) tuples.

    Updates inode in memory. Caller must call write_inode() after.
    """
    blocksize = sb['sb_blocksize']

    # Need extent-based storage
    blocks_needed = (len(data) + blocksize - 1) // blocksize
    if blocks_needed == 0:
        blocks_needed = 1

    # Free old extents first
    if inode['di_format'] == XFS_DINODE_FMT_EXTENTS and inode['di_nextents'] > 0:
        old_extents = get_extents(f, part_offset, sb, inode)
        # TODO: free old blocks via free_fn
    elif inode['di_format'] == XFS_DINODE_FMT_LOCAL:
        pass  # no blocks to free

    # Allocate new blocks
    allocations = alloc_fn(f, part_offset, sb, blocks_needed)

    # Write data to allocated blocks
    data_offset = 0
    for fsblock, count in allocations:
        disk_off = fsblock_to_offset(sb, part_offset, fsblock)
        f.seek(disk_off)
        chunk_size = count * blocksize
        chunk = data[data_offset:data_offset + chunk_size]
        # Pad to full block boundary
        if len(chunk) < chunk_size:
            chunk = chunk + b'\x00' * (chunk_size - len(chunk))
        f.write(chunk)
        data_offset += chunk_size

    # Build extent list
    extents = []
    file_off = 0
    for fsblock, count in allocations:
        extents.append((file_off, fsblock, count))
        file_off += count

    set_extents(inode, sb, extents)
    inode['di_size'] = len(data)


def read_symlink(f, part_offset, sb, inode):
    """Read symlink target from XFS inode. Returns string."""
    data = read_file_data(f, part_offset, sb, inode)
    return data.rstrip(b'\x00').decode('utf-8', errors='replace')


# ── Private: B+tree extent reading ─────────────────────────────────

def _btree_get_extents(f, part_offset, sb, fork_data):
    """Read extents from a B+tree rooted in the data fork.

    Migrated from sgi_fs.py _xfs_btree_get_extents().
    """
    if len(fork_data) < 4:
        return []

    # On-disk root: xfs_bmdr_block_t (4 bytes header)
    level, numrecs = struct.unpack('>HH', fork_data[0:4])

    if numrecs == 0 or level > 10:
        return []

    if level == 0:
        # Leaf — records directly in fork
        extents = []
        for i in range(numrecs):
            rec_off = 4 + i * 16
            if rec_off + 16 > len(fork_data):
                break
            startoff, startblock, blockcount, flag = parse_bmbt_rec(
                fork_data[rec_off:rec_off + 16])
            if blockcount > 0:
                extents.append((startoff, startblock, blockcount))
        return extents

    # Internal node — keys then pointers
    header_size = 4
    key_size = 8
    ptr_size = 8
    dmxr = (len(fork_data) - header_size) // (key_size + ptr_size)
    keys_off = header_size
    ptrs_off = keys_off + dmxr * key_size

    if ptrs_off + 8 > len(fork_data):
        return []

    bno = struct.unpack('>Q', fork_data[ptrs_off:ptrs_off + 8])[0]
    blocksize = sb['sb_blocksize']

    if not valid_fsblock(bno):
        return []

    # Walk down to leaf level
    cur_level = level
    while cur_level > 0:
        disk_off = fsblock_to_offset(sb, part_offset, bno)
        f.seek(disk_off)
        block_data = f.read(blocksize)
        if len(block_data) < 24:
            return []

        blk_magic, blk_level, blk_numrecs = struct.unpack('>IHH', block_data[0:8])
        if blk_magic != XFS_BMAP_MAGIC:
            return []

        cur_level = blk_level
        if cur_level > 0:
            # Internal — follow first pointer
            ptr_start = 24 + blk_numrecs * 8
            if ptr_start + 8 > len(block_data):
                return []
            bno = struct.unpack('>Q', block_data[ptr_start:ptr_start + 8])[0]
            if not valid_fsblock(bno):
                return []

    # Walk leaf linked list
    extents = []
    visited = set()
    while valid_fsblock(bno) and bno not in visited:
        visited.add(bno)
        disk_off = fsblock_to_offset(sb, part_offset, bno)
        f.seek(disk_off)
        block_data = f.read(blocksize)
        if len(block_data) < 24:
            break

        blk_magic, blk_level, blk_numrecs = struct.unpack('>IHH', block_data[0:8])
        if blk_magic != XFS_BMAP_MAGIC:
            break
        blk_leftsib, blk_rightsib = struct.unpack('>QQ', block_data[8:24])

        for i in range(blk_numrecs):
            rec_off = 24 + i * 16
            if rec_off + 16 > len(block_data):
                break
            startoff, startblock, blockcount, flag = parse_bmbt_rec(
                block_data[rec_off:rec_off + 16])
            if blockcount > 0:
                extents.append((startoff, startblock, blockcount))

        bno = blk_rightsib

    return extents
