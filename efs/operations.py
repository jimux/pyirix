"""High-level EFS operations: create_file / write_file, done IN PLACE.

Companion to pyirix.xfs.operations, but for SGI EFS. Unlike
pyirix.efs.builder (an mkfs-style whole-image builder), this module edits an
EXISTING EFS filesystem: it allocates a free inode and free data blocks from
the filesystem's own bitmap/CG layout, writes the new file's extents, adds a
directory entry (extending the directory's own data if it doesn't fit), and
patches the superblock's free counters + checksum. It never touches
`fs_ncg`/`fs_cgfsize`/`fs_tinode`(capacity)/`fs_size` (the filesystem's
geometry) and never rewrites the whole partition.

Bug 1: sgi_mcp.sgi_fs.fs_inject()'s EFS branch used to extract every file,
then call EFSBuilder(size_mb) to rebuild the WHOLE partition from scratch.
EFSBuilder derives cylinder-group/inode counts from size alone, so the
rebuilt image had a different geometry than the source (e.g. fs_ncg 80 -> 260,
fs_tinode capacity 842558 -> 8320), and then the padding write blew past
quota. See progress_notes / tmp/Orchestrator/2026-09-24-fs-tools/
92-pyirix-fs_inject-efs-mis-size.md for the full writeup.

Bug 2 (found testing bug 1's fix against a REAL IRIX EFS golden, not just a
synthetic mkfs_efs image): `fs_bmblock` is 0 on every filesystem that has
never been grown -- real IRIX never bothers to write the default value, it
just relies on the kernel's fallback (`efs_bitmap.c`: `bmbase = fs->fs_bmblock
? fs->fs_bmblock : EFS_BITMAPBB`, EFS_BITMAPBB == 2). Addressing the bitmap
at `fs_bmblock * EFS_BLOCK_SIZE` when fs_bmblock == 0 puts it at basic block
0 -- the boot block and the superblock -- so every inject corrupted the
superblock (fs_size 8302589 -> 13 on one real image) and, since the "bitmap"
read back was actually boot-block/superblock bytes reinterpreted as free-bit
data, allocation saw the disk as almost entirely full and wildly fragmented.
Confirmed against real IRIX kernel source (sys/fs/efs_fs.h, efs_bitmap.c).

Bug 3 (same investigation): the free-block search used simple first-fit
starting at block 0, so it could report "not enough space" or "too
fragmented" long before actually exhausting the real free-run inventory, and
had no path for a file needing more than 12 fragments. Fixed by scanning the
WHOLE bitmap once for every free run, always consuming runs LARGEST-first
(minimizes the extent count for a given amount of fragmentation), and by
supporting indirect extents (mirrors pyirix.efs.builder's whole-image-builder
format, confirmed against sys/fs/efs_ino.h: up to EFS_DIRECTEXTENTS=12
indirect-table blocks, each up to EFS_MAXINDIRBBS=64 basic blocks, holding
EFS_BLOCK_SIZE/8=64 packed extent descriptors apiece) the way real IRIX does.
If a file is so fragmented it needs more indirect-table blocks than that, the
whole operation raises EFSNoSpaceError BEFORE any bitmap/data/inode byte is
written to disk (allocation planning happens entirely in memory first).
"""

import struct
import time

from pyirix.efs.reader import (
    EFS_MAGIC, EFS_MAGIC_NEW, EFS_BLOCK_SIZE, EFS_INOPBB, EFS_INODE_SIZE,
    EFS_ROOT_INODE, EFS_MAX_EXTENTS, EFS_DIRBLK_MAGIC,
    S_IFMT, S_IFDIR, S_IFREG, S_IFLNK,
    inode_to_bb, read_inode as _reader_read_inode, parse_extent,
    get_all_extents,
)
from pyirix.efs.builder import (
    pack_extent, pack_inode, build_dir_blocks, EFS_MAX_EXTENT_LENGTH,
)
from pyirix.efs.repair import compute_checksum


class EFSError(Exception):
    pass


class EFSPathError(EFSError):
    pass


class EFSExistsError(EFSError):
    pass


class EFSNoSpaceError(EFSError):
    pass


# First inode number that's ever handed out.  0 and 1 are reserved (no
# real EFS file uses them — EFSImageBuilder starts its own allocator at
# EFS_ROOT_INODE + 1 == 3 for the same reason), and 2 is the root, which
# always exists already.
_FIRST_ALLOCATABLE_INODE = EFS_ROOT_INODE + 1

# sys/fs/efs_ino.h: "up to EFS_DIRECTEXTENTS contiguous blocks of indirect
# extents"; "The inode code expects to be able to handle indirect extents in
# ONE buffer ... EFS_MAXINDIRBBS 64". Each indirect-table block holds
# EFS_BLOCK_SIZE/8 packed 8-byte extent descriptors.
EFS_MAXINDIRBBS = 64
_EXTENTS_PER_INDIRECT_BLOCK = EFS_BLOCK_SIZE // 8


# ── Directory entries (RAW — including '.' / '..') ──────────────────
#
# pyirix.efs.reader.read_dir_entries() filters out '.' and '..' for
# display purposes. An in-place writer must NOT do that: if we rebuilt a
# directory's blocks from the filtered list we would silently drop its
# dot-entries every time a file is injected. So this module keeps its own
# raw reader that preserves every entry exactly as stored.

def _read_raw_dir_entries(f, part_offset, inode):
    """Read ALL directory entries (including '.' and '..'), in on-disk
    slot order, as a list of (name, ino)."""
    entries = []
    extents = get_all_extents(f, part_offset, inode)
    for ext in extents:
        f.seek(part_offset + ext['bn'] * EFS_BLOCK_SIZE)
        ext_data = f.read(ext['length'] * EFS_BLOCK_SIZE)
        for blk_off in range(0, len(ext_data), EFS_BLOCK_SIZE):
            dirblk = ext_data[blk_off:blk_off + EFS_BLOCK_SIZE]
            if len(dirblk) < EFS_BLOCK_SIZE:
                break
            magic = struct.unpack('>H', dirblk[0:2])[0]
            if magic != EFS_DIRBLK_MAGIC:
                continue
            firstused = dirblk[2]
            slots = dirblk[3]
            for slot in range(slots):
                slot_val = dirblk[4 + slot]
                if slot_val < firstused:
                    continue
                entry_off = slot_val * 2
                if entry_off + 5 > EFS_BLOCK_SIZE:
                    continue
                ino = struct.unpack('>I', dirblk[entry_off:entry_off + 4])[0]
                namelen = dirblk[entry_off + 4]
                if entry_off + 5 + namelen > EFS_BLOCK_SIZE:
                    continue
                name = dirblk[entry_off + 5:entry_off + 5 + namelen].decode(
                    'ascii', errors='replace')
                entries.append((name, ino))
    return entries


# ── Path resolution ──────────────────────────────────────────────────

def resolve_path(f, part_offset, sb, path):
    """Resolve a path to an EFS inode number (not following symlinks).
    Returns None if any component doesn't exist."""
    parts = [p for p in path.strip('/').split('/') if p]
    if not parts:
        return EFS_ROOT_INODE
    current = EFS_ROOT_INODE
    for part in parts:
        inode = _reader_read_inode(f, part_offset, sb, current)
        if not inode or (inode['mode'] & S_IFMT) != S_IFDIR:
            return None
        found = None
        for name, ino in _read_raw_dir_entries(f, part_offset, inode):
            if name == part:
                found = ino
                break
        if found is None:
            return None
        current = found
    return current


def resolve_parent(f, part_offset, sb, path):
    """Return (parent_ino, basename). Raises EFSPathError if the parent
    doesn't exist or isn't a directory."""
    path = '/' + path.strip('/')
    parent_path, _, basename = path.rpartition('/')
    if not basename:
        raise EFSPathError(f"Invalid path: {path}")
    parent_ino = resolve_path(f, part_offset, sb, parent_path or '/')
    if parent_ino is None:
        raise EFSPathError(f"Parent directory not found: {parent_path or '/'}")
    parent_inode = _reader_read_inode(f, part_offset, sb, parent_ino)
    if not parent_inode or (parent_inode['mode'] & S_IFMT) != S_IFDIR:
        raise EFSPathError(f"Not a directory: {parent_path or '/'}")
    return parent_ino, basename


# ── Free-space allocation (existing bitmap / CG layout, untouched) ──
#
# Two facts, both confirmed against real IRIX kernel source
# (sys/fs/efs_fs.h, sys/fs/efs_bitmap.c), not guessed:
#
# 1. `fs_bmblock` is 0 on every filesystem that has never been grown --
#    that's not "uninitialized", it's the documented convention. The
#    kernel's own bitmap-base helper is `bmbase = fs->fs_bmblock ?
#    fs->fs_bmblock : EFS_BITMAPBB` (EFS_BITMAPBB == 2). Do the same here.
# 2. `fs_bmsize` is a BYTE count, not a block count ("Basic blocks 2
#    through 2 + BTOD(fs->fs_bmsize) - 1", BTOD = bytes-to-disk-blocks),
#    matching how pyirix.efs.builder.pack_superblock() is called
#    (bmsize=bm_bytes).

def _bmbase(sb):
    return sb['fs_bmblock'] if sb['fs_bmblock'] else 2


def _read_bitmap(f, part_offset, sb):
    f.seek(part_offset + _bmbase(sb) * EFS_BLOCK_SIZE)
    return bytearray(f.read(sb['fs_bmsize']))


def _write_bitmap(f, part_offset, sb, bitmap):
    f.seek(part_offset + _bmbase(sb) * EFS_BLOCK_SIZE)
    f.write(bytes(bitmap))


def _bit_free(bitmap, block_num):
    return bool(bitmap[block_num // 8] & (1 << (7 - (block_num % 8))))


def _mark_allocated(bitmap, block_num):
    bitmap[block_num // 8] &= ~(1 << (7 - (block_num % 8)))


def _mark_free(bitmap, block_num):
    bitmap[block_num // 8] |= (1 << (7 - (block_num % 8)))


def _free_extents(bitmap, extents):
    """extents: iterable of (bn, length). Marks every block in them free
    again (used when overwriting/extending discards old blocks)."""
    for bn, length in extents:
        for b in range(bn, bn + length):
            _mark_free(bitmap, b)


def _find_free_runs(bitmap, fs_size):
    """Every maximal run of free blocks in `bitmap`, as (start, length),
    in ascending block-number order. A single pass over the whole
    filesystem, so it sees free space in every cylinder group, not just
    whatever's near block 0."""
    runs = []
    b = 0
    while b < fs_size:
        if not _bit_free(bitmap, b):
            b += 1
            continue
        start = b
        while b < fs_size and _bit_free(bitmap, b):
            b += 1
        runs.append((start, b - start))
    return runs


def _alloc_blocks(bitmap, fs_size, nblocks, max_run=EFS_MAX_EXTENT_LENGTH):
    """Allocate `nblocks` free blocks from `bitmap` (mutated in place).

    Finds every free run across the WHOLE filesystem first, then consumes
    them LARGEST-first — this minimizes the number of extents needed for
    a given amount of free-space fragmentation (a naive first-fit-from-
    block-0 scan can need far more extents, or even wrongly report "not
    enough space", when the earliest free blocks happen to be scattered
    in small runs while big contiguous runs sit later in the filesystem).
    A run longer than `max_run` basic blocks is split into multiple
    extents (an EFS extent's length field is one byte: EFS_MAXEXTENTLEN
    == 248 for data, EFS_MAXINDIRBBS == 64 for indirect-table blocks).

    Returns a list of (bn, length) in ascending block-number order (NOT
    necessarily file-logical order — callers needing file-logical extent
    order should sort or track that themselves; both current callers just
    concatenate data sequentially, so ascending-by-allocation is fine).
    Raises EFSNoSpaceError if the true total free space is insufficient.
    Never raises for fragmentation alone -- that is the caller's call
    (direct vs indirect extent representation).
    """
    if nblocks == 0:
        return []

    runs = _find_free_runs(bitmap, fs_size)
    total_free = sum(length for _, length in runs)
    if total_free < nblocks:
        raise EFSNoSpaceError(
            f"Not enough free space: needed {nblocks} blocks, "
            f"{total_free} found")

    runs.sort(key=lambda r: r[1], reverse=True)
    extents = []
    remaining = nblocks
    for start, length in runs:
        if remaining <= 0:
            break
        take = min(length, remaining)
        pos = start
        left = take
        while left > 0:
            chunk = min(left, max_run)
            extents.append((pos, chunk))
            pos += chunk
            left -= chunk
        remaining -= take

    if remaining > 0:
        # total_free already proved this can't happen; stay safe anyway.
        raise EFSNoSpaceError(
            f"Not enough free space: needed {nblocks} blocks, "
            f"{nblocks - remaining} found")

    for bn, length in extents:
        for b in range(bn, bn + length):
            _mark_allocated(bitmap, b)

    extents.sort(key=lambda e: e[0])
    return extents


def _alloc_inode(f, part_offset, sb):
    """Scan the existing CG inode areas for a free (mode == 0) inode
    slot. Does not touch the bitmap (inode-area blocks are already
    marked allocated for the whole CG at mkfs time)."""
    cgisize = sb['fs_cgisize']
    ncg = sb['fs_ncg']
    ipcg = cgisize * EFS_INOPBB
    total = ncg * ipcg
    ino = _FIRST_ALLOCATABLE_INODE
    while ino < total:
        bb = inode_to_bb(sb, ino)
        f.seek(part_offset + bb * EFS_BLOCK_SIZE)
        block = f.read(EFS_BLOCK_SIZE)
        base_ino = ino - (ino & 0x3)
        for slot in range(ino & 0x3, EFS_INOPBB):
            candidate = base_ino + slot
            if candidate >= total:
                break
            mode = struct.unpack(
                '>H', block[slot * EFS_INODE_SIZE:slot * EFS_INODE_SIZE + 2])[0]
            if mode == 0:
                return candidate
        ino = base_ino + EFS_INOPBB
    raise EFSNoSpaceError("No free inodes")


# ── Extent-table packing: direct or indirect, exactly like real IRIX ──
#
# sys/fs/efs_ino.h: "Inodes consist of some number of extents ... When
# di_numextents exceeds EFS_DIRECTEXTENTS[12], the extents are kept
# elsewhere ... a list of up to EFS_DIRECTEXTENTS contiguous blocks of
# indirect extents ... For indirect extents the field
# di_u.di_extents[0].ex_offset contains the number of indirect extents."
# Matches pyirix.efs.builder.EFSImageBuilder._build_indirect_extents,
# which this reuses the on-disk shape of (not the code, since that class
# plans a whole-image build rather than allocating from a live bitmap).

def _pack_extents_for_inode(bitmap, fs_size, raw_data_extents):
    """raw_data_extents: (bn, length) pairs already allocated on `bitmap`,
    in the order they should appear in the file (ascending bn is fine —
    _alloc_blocks returns them in exactly the order they were consumed).

    Returns (numextents, ext_bytes, indirect_writes):
      numextents  — value for the inode's di_numextents (== number of DATA
                    extents, whether stored directly or indirectly).
      ext_bytes   — the up-to-96 bytes to store at inode offset 32 (either
                    the packed direct data extents, or the packed indirect
                    pointer extents).
      indirect_writes — [] for the direct case; otherwise a list of
                    (bn, bytes) raw blocks to also write to disk, holding
                    the actual packed data-extent table.

    Raises EFSNoSpaceError (before touching `bitmap` any further, and
    before the caller has written anything to disk) if even indirect
    extents can't represent this many fragments.
    """
    data_extents = _extents_with_offsets(raw_data_extents)

    if len(data_extents) <= EFS_MAX_EXTENTS:
        ext_bytes = b''.join(pack_extent(0, bn, length, offset)
                             for bn, length, offset in data_extents)
        return len(data_extents), ext_bytes, []

    # Indirect: pack every data extent into an 8-byte descriptor table,
    # then allocate blocks (<=64 bb per run) to hold that table.
    ext_table = b''.join(pack_extent(0, bn, length, offset)
                         for bn, length, offset in data_extents)
    indirect_blocks_needed = (
        (len(data_extents) + _EXTENTS_PER_INDIRECT_BLOCK - 1)
        // _EXTENTS_PER_INDIRECT_BLOCK)

    indirect_raw = _alloc_blocks(bitmap, fs_size, indirect_blocks_needed,
                                 max_run=EFS_MAXINDIRBBS)
    if len(indirect_raw) > EFS_MAX_EXTENTS:
        # Free what we just marked for the indirect table before raising —
        # the data extents themselves are the CALLER's to free (it knows
        # whether they came from a fresh alloc or a caller-owned bitmap it
        # will discard entirely on error).
        _free_extents(bitmap, indirect_raw)
        raise EFSNoSpaceError(
            f"File needs {len(data_extents)} data extents "
            f"({indirect_blocks_needed} indirect-table blocks) but free "
            f"space is fragmented into more than {EFS_MAX_EXTENTS} runs "
            f"even for the indirect-table blocks themselves — real IRIX "
            f"could not represent this file either")

    indirect_writes = []
    table_offset = 0
    for bn, length in indirect_raw:
        chunk_size = length * EFS_BLOCK_SIZE
        chunk = ext_table[table_offset:table_offset + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b'\x00' * (chunk_size - len(chunk))
        indirect_writes.append((bn, chunk))
        table_offset += chunk_size

    num_indirect = len(indirect_raw)
    inode_ext_bytes = b''
    for i, (bn, length) in enumerate(indirect_raw):
        offset = num_indirect if i == 0 else 0
        inode_ext_bytes += pack_extent(0, bn, length, offset)

    return len(data_extents), inode_ext_bytes, indirect_writes


def _inode_owned_blocks(inode, data_extents):
    """All (bn, length) blocks physically owned by `inode`: its data
    blocks, plus — for an inode using indirect extents — the indirect
    extent-table blocks themselves (the up-to-12 raw entries stored
    directly in the inode ARE those table-block pointers in that case,
    not data)."""
    owned = [(e['bn'], e['length']) for e in data_extents]
    if inode['numextents'] > EFS_MAX_EXTENTS:
        owned += [(e['bn'], e['length']) for e in inode['extents']]
    return owned


# ── Raw inode / data writers ─────────────────────────────────────────

def _write_inode_packed(f, part_offset, sb, ino, mode, nlink, uid, gid,
                        size, mtime, numextents, ext_bytes):
    bb = inode_to_bb(sb, ino)
    slot = ino & 0x3
    inode_bytes = pack_inode(mode, nlink, uid, gid, size, mtime,
                             numextents, ext_bytes)
    f.seek(part_offset + bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE)
    f.write(inode_bytes)


def _patch_inode_size_mtime(f, part_offset, sb, ino, size, mtime):
    """Update only size/atime/mtime/ctime, leaving the extent table (and
    everything else) byte-for-byte untouched. Used when a directory's new
    contents still fit in its already-allocated blocks."""
    bb = inode_to_bb(sb, ino)
    slot = ino & 0x3
    pos = part_offset + bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE
    f.seek(pos)
    buf = bytearray(f.read(EFS_INODE_SIZE))
    struct.pack_into('>i', buf, 8, size)
    struct.pack_into('>i', buf, 12, mtime)   # atime
    struct.pack_into('>i', buf, 16, mtime)   # mtime
    struct.pack_into('>i', buf, 20, mtime)   # ctime
    f.seek(pos)
    f.write(bytes(buf))


def _extents_with_offsets(raw_extents):
    """raw_extents: list of (bn, length) -> list of (bn, length, offset)
    with `offset` the cumulative logical block position (matches
    EFSImageBuilder._allocate_blocks)."""
    out = []
    running = 0
    for bn, length in raw_extents:
        out.append((bn, length, running))
        running += length
    return out


def _write_data_to_extents(f, part_offset, extents, data):
    """extents: list of (bn, length[, offset]) in logical order. Writes
    `data` sequentially across them."""
    pos = 0
    for ext in extents:
        bn, length = ext[0], ext[1]
        chunk_len = length * EFS_BLOCK_SIZE
        chunk = data[pos:pos + chunk_len]
        if len(chunk) < chunk_len:
            chunk = chunk + b'\x00' * (chunk_len - len(chunk))
        f.seek(part_offset + bn * EFS_BLOCK_SIZE)
        f.write(chunk)
        pos += chunk_len


def _write_raw_blocks(f, part_offset, writes):
    """writes: list of (bn, bytes) — used for indirect extent-table
    blocks, which aren't file data."""
    for bn, chunk in writes:
        f.seek(part_offset + bn * EFS_BLOCK_SIZE)
        f.write(chunk)


# ── Superblock patch (only the free counters + checksum) ────────────

def _patch_superblock_counters(f, part_offset, sb, delta_tfree, delta_tinode):
    """Adjust fs_tfree/fs_tinode by the given deltas (may be negative) and
    recompute+rewrite the checksum, touching NOTHING else in the
    superblock. Patches both the primary superblock and its replica at
    fs_replsb if that replica still carries a valid EFS magic."""
    new_tfree = sb['fs_tfree'] + delta_tfree
    new_tinode = sb['fs_tinode'] + delta_tinode

    locations = [part_offset + EFS_BLOCK_SIZE]
    replsb_off = part_offset + sb['fs_replsb'] * EFS_BLOCK_SIZE
    f.seek(replsb_off)
    repl_data = f.read(EFS_BLOCK_SIZE)
    if (len(repl_data) == EFS_BLOCK_SIZE
            and struct.unpack('>I', repl_data[28:32])[0]
            in (EFS_MAGIC, EFS_MAGIC_NEW)):
        locations.append(replsb_off)

    for loc in locations:
        f.seek(loc)
        buf = bytearray(f.read(EFS_BLOCK_SIZE))
        struct.pack_into('>i', buf, 48, new_tfree)
        struct.pack_into('>i', buf, 52, new_tinode)
        struct.pack_into('>i', buf, 88, 0)  # zero checksum before computing
        checksum = compute_checksum(bytes(buf))  # pyirix.efs.repair — same
        struct.pack_into('>I', buf, 88, checksum & 0xFFFFFFFF)  # algorithm check_efs() verifies
        f.seek(loc)
        f.write(bytes(buf))

    sb['fs_tfree'] = new_tfree
    sb['fs_tinode'] = new_tinode


# ── Directory entry insertion (extends the dir in place if needed) ──

def _add_dir_entry(f, part_offset, sb, parent_ino, name, child_ino):
    """Append (name, child_ino) to parent_ino's directory, rebuilding
    just that directory's own blocks. Reuses the existing blocks in place
    when the new entry still fits (no bitmap change at all); otherwise
    frees everything currently owned by the directory (data blocks, and
    any indirect-table blocks) and reallocates fresh for the full new
    size — simpler and just as correct as trying to preserve old extent
    positions, and it naturally handles a directory that itself needs to
    grow from direct to indirect extents. Returns the net number of
    blocks now used by the directory that weren't before (0 if it fit in
    place) — the caller uses this to update fs_tfree."""
    parent_inode = _reader_read_inode(f, part_offset, sb, parent_ino)
    if parent_inode is None:
        raise EFSPathError("Parent inode vanished")

    entries = _read_raw_dir_entries(f, part_offset, parent_inode)
    for existing_name, _ in entries:
        if existing_name == name:
            raise EFSExistsError(f"Path already exists: {name}")
    entries.append((name, child_ino))

    new_data = build_dir_blocks(entries)
    new_blocks = len(new_data) // EFS_BLOCK_SIZE

    old_data_extents = get_all_extents(f, part_offset, parent_inode)
    old_raw = [(e['bn'], e['length']) for e in old_data_extents]
    old_block_count = sum(length for _, length in old_raw)

    now = int(time.time())

    if new_blocks <= old_block_count:
        # Fits in the already-allocated blocks -- no bitmap change, no
        # extent-table change, just new content + size/mtime.
        _write_data_to_extents(f, part_offset, _extents_with_offsets(old_raw),
                               new_data)
        _patch_inode_size_mtime(f, part_offset, sb, parent_ino,
                                len(new_data), now)
        return 0

    old_table_blocks = 0
    if parent_inode['numextents'] > EFS_MAX_EXTENTS:
        old_table_blocks = sum(e['length'] for e in parent_inode['extents'])

    bitmap = _read_bitmap(f, part_offset, sb)
    _free_extents(bitmap, _inode_owned_blocks(parent_inode, old_data_extents))

    raw_data_extents = _alloc_blocks(bitmap, sb['fs_size'], new_blocks)
    numextents, ext_bytes, indirect_writes = _pack_extents_for_inode(
        bitmap, sb['fs_size'], raw_data_extents)

    _write_data_to_extents(f, part_offset, _extents_with_offsets(raw_data_extents),
                           new_data)
    _write_raw_blocks(f, part_offset, indirect_writes)
    _write_inode_packed(f, part_offset, sb, parent_ino, parent_inode['mode'],
                        parent_inode['nlink'], parent_inode['uid'],
                        parent_inode['gid'], len(new_data), now,
                        numextents, ext_bytes)
    _write_bitmap(f, part_offset, sb, bitmap)

    new_table_blocks = sum(len(chunk) // EFS_BLOCK_SIZE
                           for _, chunk in indirect_writes)
    new_total = new_blocks + new_table_blocks
    old_total = old_block_count + old_table_blocks
    return new_total - old_total


# ── Public API ────────────────────────────────────────────────────────

def create_file(f, part_offset, sb, path, data, mode=0o100644, uid=0, gid=0):
    """Create a new regular file at `path` with `data`, entirely in
    place: allocates one free inode + free data blocks from the
    filesystem's existing bitmap/CG layout, writes the extents (direct,
    or indirect if the file needs more than 12 fragments), adds the
    directory entry (extending the parent directory if it doesn't have
    room), and patches the superblock's free counters + checksum. Never
    touches fs_ncg/fs_cgfsize/fs_size/inode-capacity and never rewrites
    the partition.

    Returns the new inode number. Raises EFSExistsError /
    EFSPathError / EFSNoSpaceError -- and on EFSNoSpaceError, nothing has
    been written to disk yet (allocation is planned in memory first).
    """
    if resolve_path(f, part_offset, sb, path) is not None:
        raise EFSExistsError(f"Path already exists: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    nblocks = (len(data) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
    bitmap = _read_bitmap(f, part_offset, sb)
    raw_extents = _alloc_blocks(bitmap, sb['fs_size'], nblocks)
    numextents, ext_bytes, indirect_writes = _pack_extents_for_inode(
        bitmap, sb['fs_size'], raw_extents)
    extents = _extents_with_offsets(raw_extents)
    # Persist the bitmap NOW, before _add_dir_entry does its own
    # independent read/allocate/write of the bitmap below — otherwise it
    # would read a stale on-disk copy that doesn't yet know these blocks
    # are taken and could hand out the same blocks twice.
    _write_bitmap(f, part_offset, sb, bitmap)

    new_ino = _alloc_inode(f, part_offset, sb)

    _write_data_to_extents(f, part_offset, extents, data)
    _write_raw_blocks(f, part_offset, indirect_writes)

    now = int(time.time())
    _write_inode_packed(f, part_offset, sb, new_ino, mode, 1, uid, gid,
                        len(data), now, numextents, ext_bytes)

    # Directory entry insertion may itself need more blocks; it reads
    # its own fresh copy of the parent inode, so do it AFTER this
    # file's own inode/data are already on disk (a partial file is
    # harmless; a dangling dir entry to a half-written inode is not).
    dir_extra_blocks = _add_dir_entry(f, part_offset, sb, parent_ino,
                                      basename, new_ino)

    table_blocks = sum(len(chunk) // EFS_BLOCK_SIZE for _, chunk in indirect_writes)
    total_blocks_used = nblocks + table_blocks + dir_extra_blocks
    _patch_superblock_counters(f, part_offset, sb,
                               delta_tfree=-total_blocks_used,
                               delta_tinode=-1)

    return new_ino


def write_file(f, part_offset, sb, path, data):
    """Overwrite an existing regular file's contents in place: frees its
    old data blocks (and any indirect-table blocks) back to the bitmap,
    allocates fresh ones for the new data (direct or indirect as needed),
    and rewrites its inode. The inode number and directory entry are
    unchanged. Raises EFSPathError if `path` doesn't resolve to an
    existing regular file."""
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise EFSPathError(f"File not found: {path}")
    inode = _reader_read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise EFSPathError(f"Cannot read inode for: {path}")
    if (inode['mode'] & S_IFMT) != S_IFREG:
        raise EFSPathError(f"Not a regular file: {path}")

    old_data_extents = get_all_extents(f, part_offset, inode)
    old_raw = [(e['bn'], e['length']) for e in old_data_extents]
    old_block_count = sum(length for _, length in old_raw)
    old_table_blocks = 0
    if inode['numextents'] > EFS_MAX_EXTENTS:
        old_table_blocks = sum(e['length'] for e in inode['extents'])

    nblocks = (len(data) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE

    bitmap = _read_bitmap(f, part_offset, sb)
    _free_extents(bitmap, _inode_owned_blocks(inode, old_data_extents))

    raw_extents = _alloc_blocks(bitmap, sb['fs_size'], nblocks)
    numextents, ext_bytes, indirect_writes = _pack_extents_for_inode(
        bitmap, sb['fs_size'], raw_extents)
    extents = _extents_with_offsets(raw_extents)

    _write_bitmap(f, part_offset, sb, bitmap)
    _write_data_to_extents(f, part_offset, extents, data)
    _write_raw_blocks(f, part_offset, indirect_writes)

    now = int(time.time())
    _write_inode_packed(f, part_offset, sb, ino, inode['mode'], inode['nlink'],
                        inode['uid'], inode['gid'], len(data), now,
                        numextents, ext_bytes)

    new_table_blocks = sum(len(chunk) // EFS_BLOCK_SIZE
                           for _, chunk in indirect_writes)
    new_total = nblocks + new_table_blocks
    old_total = old_block_count + old_table_blocks
    _patch_superblock_counters(f, part_offset, sb,
                               delta_tfree=old_total - new_total,
                               delta_tinode=0)
