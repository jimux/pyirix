"""High-level EFS operations: create_file / write_file, done IN PLACE.

Companion to pyirix.xfs.operations, but for SGI EFS. Unlike
pyirix.efs.builder (an mkfs-style whole-image builder), this module edits an
EXISTING EFS filesystem: it allocates a free inode and free data blocks from
the filesystem's own bitmap/CG layout, writes the new file's extents, adds a
directory entry (extending the directory's own data if it doesn't fit), and
patches the superblock's free counters + checksum. It never touches
`fs_ncg`/`fs_cgfsize`/`fs_tinode`(capacity)/`fs_size` (the filesystem's
geometry) and never rewrites the whole partition.

Bug: sgi_mcp.sgi_fs.fs_inject()'s EFS branch used to extract every file,
then call EFSBuilder(size_mb) to rebuild the WHOLE partition from scratch.
EFSBuilder derives cylinder-group/inode counts from size alone, so the
rebuilt image had a different geometry than the source (e.g. fs_ncg 80 -> 260,
fs_tinode capacity 842558 -> 8320), and then the padding write blew past
quota. See progress_notes / tmp/Orchestrator/2026-09-24-fs-tools/
92-pyirix-fs_inject-efs-mis-size.md for the full writeup.
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
# `fs_bmsize` is a BYTE count, not a block count — confirmed against the
# real IRIX kernel header (sys/fs/efs_fs.h): "Basic blocks 2 through
# 2 + BTOD(fs->fs_bmsize) - 1" (BTOD = bytes-to-disk-blocks), and matches
# how pyirix.efs.builder.pack_superblock() is called (bmsize=bm_bytes).
# Reading/writing `fs_bmsize * EFS_BLOCK_SIZE` bytes here previously over-read
# by ~512x, capturing a stale snapshot that ran straight through the CG0
# inode area — writing it back later silently reverted any inode just
# written in between (e.g. a directory's own inode, right after extending
# it), corrupting the just-added entries with no error.

def _read_bitmap(f, part_offset, sb):
    f.seek(part_offset + sb['fs_bmblock'] * EFS_BLOCK_SIZE)
    return bytearray(f.read(sb['fs_bmsize']))


def _write_bitmap(f, part_offset, sb, bitmap):
    f.seek(part_offset + sb['fs_bmblock'] * EFS_BLOCK_SIZE)
    f.write(bytes(bitmap))


def _bit_free(bitmap, block_num):
    return bool(bitmap[block_num // 8] & (1 << (7 - (block_num % 8))))


def _mark_allocated(bitmap, block_num):
    bitmap[block_num // 8] &= ~(1 << (7 - (block_num % 8)))


def _alloc_blocks(bitmap, fs_size, nblocks, max_extents=EFS_MAX_EXTENTS):
    """Allocate `nblocks` free blocks from `bitmap` (mutated in place),
    packed into as few extents as possible (runs up to
    EFS_MAX_EXTENT_LENGTH each). Returns a list of (bn, length) in
    ascending block order. Raises EFSNoSpaceError if there isn't enough
    free space, or if it can't be packed into `max_extents` direct
    extents (this writer does not create indirect extent blocks)."""
    if nblocks == 0:
        return []
    extents = []
    remaining = nblocks
    b = 0
    while remaining > 0 and b < fs_size:
        if not _bit_free(bitmap, b):
            b += 1
            continue
        run_start = b
        run_len = 0
        while (b < fs_size and run_len < EFS_MAX_EXTENT_LENGTH
               and run_len < remaining and _bit_free(bitmap, b)):
            run_len += 1
            b += 1
        for i in range(run_start, run_start + run_len):
            _mark_allocated(bitmap, i)
        extents.append((run_start, run_len))
        remaining -= run_len
        if len(extents) > max_extents:
            raise EFSNoSpaceError(
                f"Cannot pack {nblocks} blocks into {max_extents} direct "
                f"extents (free space too fragmented)")
    if remaining > 0:
        raise EFSNoSpaceError(
            f"Not enough free space: needed {nblocks} blocks, "
            f"{nblocks - remaining} found")
    if len(extents) > max_extents:
        raise EFSNoSpaceError(
            f"Cannot pack {nblocks} blocks into {max_extents} direct "
            f"extents (free space too fragmented)")
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


# ── Raw inode / data writers ─────────────────────────────────────────

def _write_inode(f, part_offset, sb, ino, mode, nlink, uid, gid, size,
                 mtime, extents):
    bb = inode_to_bb(sb, ino)
    slot = ino & 0x3
    ext_bytes = b''.join(pack_extent(0, bn, length, offset)
                         for bn, length, offset in extents)
    inode_bytes = pack_inode(mode, nlink, uid, gid, size, mtime,
                             len(extents), ext_bytes)
    f.seek(part_offset + bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE)
    f.write(inode_bytes)


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
    just that directory's own blocks. Reuses existing blocks/extents
    when the new entry still fits; otherwise allocates additional
    blocks from the shared bitmap and extends the directory's extent
    list. Returns the net number of NEW data blocks allocated (0 if the
    existing blocks had room) — the caller uses this to update
    fs_tfree."""
    parent_inode = _reader_read_inode(f, part_offset, sb, parent_ino)
    if parent_inode is None:
        raise EFSPathError("Parent inode vanished")
    if parent_inode['numextents'] > EFS_MAX_EXTENTS:
        raise EFSError(
            "Directory uses indirect extents; in-place write not supported")

    old_extents = [(e['bn'], e['length']) for e in parent_inode['extents']]
    old_blocks = sum(length for _, length in old_extents)

    entries = _read_raw_dir_entries(f, part_offset, parent_inode)
    for existing_name, _ in entries:
        if existing_name == name:
            raise EFSExistsError(f"Path already exists: {name}")
    entries.append((name, child_ino))

    new_data = build_dir_blocks(entries)
    new_blocks = len(new_data) // EFS_BLOCK_SIZE

    bitmap = None
    extra_blocks_allocated = 0
    if new_blocks > old_blocks:
        extra_needed = new_blocks - old_blocks
        if len(old_extents) >= EFS_MAX_EXTENTS:
            raise EFSNoSpaceError(
                "Directory already has the max number of extents")
        bitmap = _read_bitmap(f, part_offset, sb)
        new_extent_budget = EFS_MAX_EXTENTS - len(old_extents)
        extra_extents = _alloc_blocks(bitmap, sb['fs_size'], extra_needed,
                                      max_extents=new_extent_budget)
        all_raw_extents = old_extents + extra_extents
        extra_blocks_allocated = extra_needed
    else:
        all_raw_extents = old_extents

    all_extents = _extents_with_offsets(all_raw_extents)
    _write_data_to_extents(f, part_offset, all_extents, new_data)

    now = int(time.time())
    _write_inode(f, part_offset, sb, parent_ino, parent_inode['mode'],
                parent_inode['nlink'], parent_inode['uid'],
                parent_inode['gid'], len(new_data), now, all_extents)

    if bitmap is not None:
        _write_bitmap(f, part_offset, sb, bitmap)

    return extra_blocks_allocated


# ── Public API ────────────────────────────────────────────────────────

def create_file(f, part_offset, sb, path, data, mode=0o100644, uid=0, gid=0):
    """Create a new regular file at `path` with `data`, entirely in
    place: allocates one free inode + free data blocks from the
    filesystem's existing bitmap/CG layout, writes the extents, adds
    the directory entry (extending the parent directory if it doesn't
    have room), and patches the superblock's free counters + checksum.
    Never touches fs_ncg/fs_cgfsize/fs_size/inode-capacity and never
    rewrites the partition.

    Returns the new inode number. Raises EFSExistsError /
    EFSPathError / EFSNoSpaceError.
    """
    if resolve_path(f, part_offset, sb, path) is not None:
        raise EFSExistsError(f"Path already exists: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    nblocks = (len(data) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
    bitmap = _read_bitmap(f, part_offset, sb)
    raw_extents = _alloc_blocks(bitmap, sb['fs_size'], nblocks)
    extents = _extents_with_offsets(raw_extents)
    # Persist the bitmap NOW, before _add_dir_entry does its own
    # independent read/allocate/write of the bitmap below — otherwise it
    # would read a stale on-disk copy that doesn't yet know these blocks
    # are taken and could hand out the same blocks twice.
    _write_bitmap(f, part_offset, sb, bitmap)

    new_ino = _alloc_inode(f, part_offset, sb)

    _write_data_to_extents(f, part_offset, extents, data)

    now = int(time.time())
    _write_inode(f, part_offset, sb, new_ino, mode, 1, uid, gid,
                len(data), now, extents)

    # Directory entry insertion may itself need more blocks; it reads
    # its own fresh copy of the parent inode, so do it AFTER this
    # file's own inode/data are already on disk (a partial file is
    # harmless; a dangling dir entry to a half-written inode is not).
    dir_extra_blocks = _add_dir_entry(f, part_offset, sb, parent_ino,
                                      basename, new_ino)

    total_blocks_used = nblocks + dir_extra_blocks
    _patch_superblock_counters(f, part_offset, sb,
                               delta_tfree=-total_blocks_used,
                               delta_tinode=-1)

    return new_ino


def write_file(f, part_offset, sb, path, data):
    """Overwrite an existing regular file's contents in place: frees its
    old data blocks back to the bitmap, allocates fresh ones for the
    new data, and rewrites its inode. The inode number and directory
    entry are unchanged. Raises EFSPathError if `path` doesn't resolve
    to an existing regular file."""
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise EFSPathError(f"File not found: {path}")
    inode = _reader_read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise EFSPathError(f"Cannot read inode for: {path}")
    if (inode['mode'] & S_IFMT) != S_IFREG:
        raise EFSPathError(f"Not a regular file: {path}")
    if inode['numextents'] > EFS_MAX_EXTENTS:
        raise EFSError(
            "File uses indirect extents; in-place write not supported")

    old_extents = [(e['bn'], e['length']) for e in inode['extents']]
    old_blocks = sum(length for _, length in old_extents)

    nblocks = (len(data) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE

    bitmap = _read_bitmap(f, part_offset, sb)
    for bn, length in old_extents:
        for b in range(bn, bn + length):
            bitmap[b // 8] |= (1 << (7 - (b % 8)))  # free it
    raw_extents = _alloc_blocks(bitmap, sb['fs_size'], nblocks)
    extents = _extents_with_offsets(raw_extents)
    _write_bitmap(f, part_offset, sb, bitmap)

    _write_data_to_extents(f, part_offset, extents, data)

    now = int(time.time())
    _write_inode(f, part_offset, sb, ino, inode['mode'], inode['nlink'],
                inode['uid'], inode['gid'], len(data), now, extents)

    _patch_superblock_counters(f, part_offset, sb,
                               delta_tfree=old_blocks - nblocks,
                               delta_tinode=0)
