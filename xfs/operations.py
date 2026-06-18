"""High-level XFS operations: create_file, write_file, mkdir, etc.

Read operations migrated from sgi_mcp/sgi_fs.py lines 975-1037.
Write operations are new.
"""

import time

from pyirix.xfs.constants import (
    S_IFMT, S_IFDIR, S_IFREG, S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO,
    XFS_DINODE_FMT_LOCAL, XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE,
    XFS_DIR_LEAF_MAGIC, XFS_DIR2_BLOCK_MAGIC,
    XFSError, XFSCorruptionError, XFSPathError,
    XFSExistsError, XFSNotEmptyError, XFSNoSpaceError,
)
from pyirix.xfs.superblock import read_superblock, write_superblock, zero_log
from pyirix.xfs.inode import (
    read_inode, write_inode, init_inode,
    read_file_data, write_file_data, read_symlink,
    get_extents,
)
from pyirix.xfs.directory import (
    read_dir_entries, read_dir_sf, read_dir_sf_parent,
    add_entry_sf, remove_entry_sf, init_dir_sf,
    add_entry_v1_leaf, remove_entry_v1_leaf,
    add_entry_dir2_block, remove_entry_dir2_block,
    sf_to_v1_leaf, sf_to_dir2_block,
)
from pyirix.xfs.ondisk import has_dirv2
from pyirix.xfs.alloc import alloc_blocks_for_file
from pyirix.xfs.ialloc import alloc_inode, free_inode


# ── Path Resolution ─────────────────────────────────────────────────

def resolve_path(f, part_offset, sb, path):
    """Resolve a path to an XFS inode number, NOT following symlinks
    in path components.

    Returns inode number or None. Use resolve_path_follow_links() if
    you want symlink-following behavior (typical for "does this file
    exist on the system" checks).
    """
    parts = [p for p in path.strip('/').split('/') if p]
    root_ino = sb['sb_rootino']
    if not parts:
        return root_ino

    current_ino = root_ino
    for part in parts:
        inode = read_inode(f, part_offset, sb, current_ino)
        if not inode or (inode['di_mode'] & S_IFMT) != S_IFDIR:
            return None
        entries = read_dir_entries(f, part_offset, sb, inode)
        found = False
        for name, child_ino in entries:
            if name == part:
                current_ino = child_ino
                found = True
                break
        if not found:
            return None
    return current_ino


def resolve_path_follow_links(f, part_offset, sb, path,
                              max_resolutions: int = 32):
    """Resolve a path, following symlinks at every level.

    IRIX makes heavy use of symlinks for path canonicalization (e.g.
    `/bin → usr/bin`, `/lib → usr/lib`). A path like `/bin/sh` won't
    resolve via `resolve_path` because `/bin` is a symlink, not a dir —
    but on the live system the lookup follows the link and finds the
    file. This function does the same, walking the link chain
    component-by-component.

    Returns the FINAL inode number (the target's inode) or None. Loops
    cap at `max_resolutions` total link traversals to defend against
    cycles.
    """
    root_ino = sb['sb_rootino']
    parts = [p for p in path.strip('/').split('/') if p]
    if not parts:
        return root_ino

    visited = 0
    current_ino = root_ino
    i = 0
    while i < len(parts):
        part = parts[i]
        inode = read_inode(f, part_offset, sb, current_ino)
        if not inode:
            return None
        ftype = inode['di_mode'] & S_IFMT
        # If the current node is a symlink, resolve IT first before
        # descending. This handles cases where an intermediate dir is
        # actually a symlink (e.g. `/bin/<foo>` with `/bin → usr/bin`).
        if ftype == S_IFLNK:
            visited += 1
            if visited > max_resolutions:
                return None
            target = read_symlink(f, part_offset, sb, inode)
            if isinstance(target, bytes):
                target = target.decode('latin-1', errors='replace')
            if not target:
                return None
            # Absolute target → reset to root; relative → splice in at
            # current position. Either way the remaining path parts
            # after `parts[i:]` (including `part` itself) are unchanged.
            new_parts = [p for p in target.split('/') if p]
            if target.startswith('/'):
                current_ino = root_ino
                parts = new_parts + parts[i:]
                i = 0
            else:
                # Relative symlink: target replaces the link's name in
                # the path. Walk into the parent (we just came down INTO
                # the link from its parent), so reset current_ino to the
                # parent of the link.
                # But: we don't easily know the parent inode here. Use
                # path-rewriting: replace parts[i-1..] with target +
                # parts[i:]. (parts[i-1] was the link's name; its parent
                # was reached by the previous component, which is what
                # current_ino's "previous state" was.)
                # Simpler: rebuild from root with the rewritten path.
                rebuilt = parts[:i] + new_parts + parts[i+1:]
                # Need to find the parent of the link to anchor the new
                # path. Easiest: restart from root.
                current_ino = root_ino
                parts = rebuilt
                i = 0
            continue

        # Not a symlink — must be a dir to descend into it.
        if ftype != S_IFDIR:
            return None

        entries = read_dir_entries(f, part_offset, sb, inode)
        found = False
        for name, child_ino in entries:
            if name == part:
                current_ino = child_ino
                found = True
                break
        if not found:
            return None
        i += 1

    # Final component might itself be a symlink — resolve once more.
    inode = read_inode(f, part_offset, sb, current_ino)
    if inode and (inode['di_mode'] & S_IFMT) == S_IFLNK and visited < max_resolutions:
        visited += 1
        target = read_symlink(f, part_offset, sb, inode)
        if isinstance(target, bytes):
            target = target.decode('latin-1', errors='replace')
        if target:
            # Resolve target from root (absolute) or from the link's
            # parent (relative). Since we don't track the parent here,
            # we resolve absolutes immediately and recursively re-call
            # for relatives using the original path's parent.
            if target.startswith('/'):
                return resolve_path_follow_links(
                    f, part_offset, sb, target,
                    max_resolutions=max_resolutions - visited)
            # Relative final-component symlink: anchor at the link's
            # parent directory.
            parent_path = '/' + '/'.join(parts[:-1])
            return resolve_path_follow_links(
                f, part_offset, sb, parent_path + '/' + target,
                max_resolutions=max_resolutions - visited)
    return current_ino


def resolve_parent(f, part_offset, sb, path):
    """Resolve the parent directory and return (parent_ino, basename).

    Raises XFSPathError if parent doesn't exist or isn't a directory.
    """
    path = path.strip('/')
    if not path:
        raise XFSPathError("Cannot resolve parent of root")

    parts = path.split('/')
    basename = parts[-1]
    parent_path = '/'.join(parts[:-1]) if len(parts) > 1 else '/'

    parent_ino = resolve_path(f, part_offset, sb, parent_path)
    if parent_ino is None:
        raise XFSPathError(f"Parent directory not found: /{parent_path}")

    parent_inode = read_inode(f, part_offset, sb, parent_ino)
    if parent_inode is None or (parent_inode['di_mode'] & S_IFMT) != S_IFDIR:
        raise XFSPathError(f"Not a directory: /{parent_path}")

    return parent_ino, basename


# ── Directory Listing ───────────────────────────────────────────────

def list_dir(f, part_offset, sb, path='/'):
    """List directory contents at path.

    Returns list of dicts: {name, ino, type, mode, uid, gid, size}.
    """
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"Path not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")
    if (inode['di_mode'] & S_IFMT) != S_IFDIR:
        raise XFSPathError(f"Not a directory: {path}")

    entries = read_dir_entries(f, part_offset, sb, inode)
    result = []
    for name, child_ino in sorted(entries):
        child = read_inode(f, part_offset, sb, child_ino)
        if child is None:
            continue
        ft = child['di_mode'] & S_IFMT
        entry = {
            'name': name,
            'ino': child_ino,
            'type': _type_char(ft),
            'mode': child['di_mode'] & 0o7777,
            'uid': child['di_uid'],
            'gid': child['di_gid'],
            'size': child['di_size'],
        }
        if ft == S_IFLNK:
            entry['link_target'] = read_symlink(f, part_offset, sb, child)
        result.append(entry)

    return result


def list_recursive(f, part_offset, sb, ino, path, results,
                   max_entries=5000, path_filter=None):
    """Recursively list directory contents.

    Migrated from sgi_fs.py _xfs_list_recursive.
    """
    if len(results) >= max_entries:
        return

    inode = read_inode(f, part_offset, sb, ino)
    if not inode:
        return

    mode = inode['di_mode']
    ft = mode & S_IFMT

    show = True
    if path_filter:
        stripped = path.lstrip('/')
        filt = path_filter.lstrip('/')
        show = (stripped == filt or stripped.startswith(filt + '/') or
                path == '/')

    if show and path != '/':
        entry = {
            'path': path,
            'type': _type_char(mode & S_IFMT),
            'perms': _format_perms(mode),
            'uid': inode['di_uid'],
            'gid': inode['di_gid'],
            'size': inode['di_size'],
        }
        if ft == S_IFLNK:
            entry['link_target'] = read_symlink(f, part_offset, sb, inode)
        results.append(entry)

    if ft == S_IFDIR:
        entries = read_dir_entries(f, part_offset, sb, inode)
        for name, child_ino in sorted(entries):
            child_path = path.rstrip('/') + '/' + name
            list_recursive(f, part_offset, sb, child_ino, child_path,
                           results, max_entries, path_filter)


def extract_recursive(f, part_offset, sb, ino, path, dest, stats=None):
    """Recursively extract files from XFS to host filesystem.

    Migrated from sgi_fs.py approach.
    """
    import os

    if stats is None:
        stats = {'files': 0, 'dirs': 0, 'symlinks': 0, 'errors': 0}

    inode = read_inode(f, part_offset, sb, ino)
    if not inode:
        stats['errors'] += 1
        return stats

    mode = inode['di_mode']
    ft = mode & S_IFMT

    host_path = os.path.join(dest, path.lstrip('/'))

    if ft == S_IFDIR:
        os.makedirs(host_path, exist_ok=True)
        stats['dirs'] += 1

        entries = read_dir_entries(f, part_offset, sb, inode)
        for name, child_ino in entries:
            child_path = path.rstrip('/') + '/' + name
            extract_recursive(f, part_offset, sb, child_ino, child_path, dest, stats)

    elif ft == S_IFREG:
        try:
            parent_dir = os.path.dirname(host_path)
            os.makedirs(parent_dir, exist_ok=True)
            data = read_file_data(f, part_offset, sb, inode)
            with open(host_path, 'wb') as out:
                out.write(data)
            stats['files'] += 1
        except Exception:
            stats['errors'] += 1

    elif ft == S_IFLNK:
        try:
            target = read_symlink(f, part_offset, sb, inode)
            parent_dir = os.path.dirname(host_path)
            os.makedirs(parent_dir, exist_ok=True)
            if os.path.lexists(host_path):
                os.unlink(host_path)
            os.symlink(target, host_path)
            stats['symlinks'] += 1
        except Exception:
            stats['errors'] += 1

    return stats


# ── Write Operations ────────────────────────────────────────────────

def create_file(f, part_offset, sb, path, data, mode=0o100644, uid=0, gid=0):
    """Create a new regular file at path with given data.

    Returns the new inode number.
    Raises XFSExistsError if path already exists.
    Raises XFSPathError if parent doesn't exist.
    """
    # Check file doesn't already exist
    existing = resolve_path(f, part_offset, sb, path)
    if existing is not None:
        raise XFSExistsError(f"Path already exists: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    # Allocate a new inode
    new_ino = alloc_inode(f, part_offset, sb)

    # Initialize the inode
    inode = init_inode(sb, mode | S_IFREG, uid=uid, gid=gid)

    # Write file data
    def _alloc(f, po, s, count):
        return alloc_blocks_for_file(f, po, s, count)

    write_file_data(f, part_offset, sb, inode, new_ino, data, _alloc)

    # Write inode to disk
    write_inode(f, part_offset, sb, new_ino, inode)

    # Add entry in parent directory
    _add_dir_entry(f, part_offset, sb, parent_ino, basename, new_ino)

    # Update superblock on disk
    write_superblock(f, part_offset, sb)

    # Zero the log to prevent stale replay
    zero_log(f, part_offset, sb)

    return new_ino


def write_file(f, part_offset, sb, path, data):
    """Overwrite an existing file's contents.

    Raises XFSPathError if file doesn't exist.
    """
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"File not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")
    if (inode['di_mode'] & S_IFMT) != S_IFREG:
        raise XFSPathError(f"Not a regular file: {path}")

    def _alloc(f, po, s, count):
        return alloc_blocks_for_file(f, po, s, count)

    write_file_data(f, part_offset, sb, inode, ino, data, _alloc)
    write_inode(f, part_offset, sb, ino, inode)

    write_superblock(f, part_offset, sb)
    zero_log(f, part_offset, sb)


def delete_file(f, part_offset, sb, path):
    """Delete a regular file.

    Frees the inode and removes the directory entry.
    Does NOT free data blocks (simplification for our use case).
    """
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"File not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")
    if (inode['di_mode'] & S_IFMT) not in (S_IFREG, S_IFLNK):
        raise XFSPathError(f"Not a regular file or symlink: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    # Remove directory entry
    _remove_dir_entry(f, part_offset, sb, parent_ino, basename)

    # Free the inode
    free_inode(f, part_offset, sb, ino)

    write_superblock(f, part_offset, sb)
    zero_log(f, part_offset, sb)


def mkdir(f, part_offset, sb, path, mode=0o40755, uid=0, gid=0):
    """Create a new directory at path.

    Returns the new inode number.
    """
    existing = resolve_path(f, part_offset, sb, path)
    if existing is not None:
        raise XFSExistsError(f"Path already exists: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    # Allocate inode
    new_ino = alloc_inode(f, part_offset, sb)

    # Initialize directory inode
    inode = init_inode(sb, mode | S_IFDIR, uid=uid, gid=gid, nlink=2)

    # Initialize shortform directory with parent pointer
    init_dir_sf(inode, sb, parent_ino)

    # Write inode
    write_inode(f, part_offset, sb, new_ino, inode)

    # Add entry in parent
    _add_dir_entry(f, part_offset, sb, parent_ino, basename, new_ino)

    # Increment parent nlink
    parent_inode = read_inode(f, part_offset, sb, parent_ino)
    if parent_inode:
        parent_inode['di_nlink'] += 1
        write_inode(f, part_offset, sb, parent_ino, parent_inode)

    write_superblock(f, part_offset, sb)
    zero_log(f, part_offset, sb)

    return new_ino


def rmdir(f, part_offset, sb, path):
    """Remove an empty directory."""
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"Directory not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")
    if (inode['di_mode'] & S_IFMT) != S_IFDIR:
        raise XFSPathError(f"Not a directory: {path}")

    # Check if empty
    entries = read_dir_entries(f, part_offset, sb, inode)
    if entries:
        raise XFSNotEmptyError(f"Directory not empty: {path}")

    parent_ino, basename = resolve_parent(f, part_offset, sb, path)

    # Remove directory entry from parent
    _remove_dir_entry(f, part_offset, sb, parent_ino, basename)

    # Decrement parent nlink
    parent_inode = read_inode(f, part_offset, sb, parent_ino)
    if parent_inode and parent_inode['di_nlink'] > 1:
        parent_inode['di_nlink'] -= 1
        write_inode(f, part_offset, sb, parent_ino, parent_inode)

    # Free the inode
    free_inode(f, part_offset, sb, ino)

    write_superblock(f, part_offset, sb)
    zero_log(f, part_offset, sb)


def chmod(f, part_offset, sb, path, mode):
    """Change file mode (permissions only, not type bits)."""
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"Path not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")

    # Preserve file type bits, replace permission bits
    inode['di_mode'] = (inode['di_mode'] & S_IFMT) | (mode & 0o7777)
    inode['di_ctime_sec'] = int(time.time())
    write_inode(f, part_offset, sb, ino, inode)


def chown(f, part_offset, sb, path, uid, gid):
    """Change file owner and group."""
    ino = resolve_path(f, part_offset, sb, path)
    if ino is None:
        raise XFSPathError(f"Path not found: {path}")

    inode = read_inode(f, part_offset, sb, ino)
    if inode is None:
        raise XFSPathError(f"Cannot read inode for: {path}")

    inode['di_uid'] = uid
    inode['di_gid'] = gid
    inode['di_ctime_sec'] = int(time.time())
    write_inode(f, part_offset, sb, ino, inode)


# ── Directory Entry Helpers ─────────────────────────────────────────

def _add_dir_entry(f, part_offset, sb, parent_ino, name, child_ino):
    """Add a directory entry, handling format conversions."""
    parent_inode = read_inode(f, part_offset, sb, parent_ino)
    if parent_inode is None:
        raise XFSCorruptionError(f"Cannot read parent inode {parent_ino}")

    fmt = parent_inode['di_format']

    if fmt == XFS_DINODE_FMT_LOCAL:
        # Try shortform first
        if add_entry_sf(parent_inode, sb, name, child_ino):
            write_inode(f, part_offset, sb, parent_ino, parent_inode)
            return

        # Shortform full — convert to block format
        def _alloc(f, po, s, count):
            return alloc_blocks_for_file(f, po, s, count)

        sf_parent = read_dir_sf_parent(parent_inode, sb)
        if sf_parent is None:
            sf_parent = parent_ino  # root dir points to itself

        if has_dirv2(sb):
            if sf_to_dir2_block(f, part_offset, sb, parent_inode, parent_ino, sf_parent, _alloc):
                if add_entry_dir2_block(f, part_offset, sb, parent_inode, name, child_ino):
                    write_inode(f, part_offset, sb, parent_ino, parent_inode)
                    return
        else:
            if sf_to_v1_leaf(f, part_offset, sb, parent_inode, parent_ino, sf_parent, _alloc):
                if add_entry_v1_leaf(f, part_offset, sb, parent_inode, name, child_ino):
                    write_inode(f, part_offset, sb, parent_ino, parent_inode)
                    return

    elif fmt in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
        # Try adding to existing block format
        extents = get_extents(f, part_offset, sb, parent_inode)
        if extents:
            from pyirix.xfs.ondisk import fsblock_to_offset
            import struct

            # Detect block type
            startoff, startblock, blockcount = extents[0]
            disk_off = fsblock_to_offset(sb, part_offset, startblock)
            f.seek(disk_off)
            header = f.read(16)

            magic2 = struct.unpack('>H', header[8:10])[0]
            magic4 = struct.unpack('>I', header[0:4])[0]

            if magic2 == XFS_DIR_LEAF_MAGIC:
                if add_entry_v1_leaf(f, part_offset, sb, parent_inode, name, child_ino):
                    return
            elif magic4 == XFS_DIR2_BLOCK_MAGIC:
                if add_entry_dir2_block(f, part_offset, sb, parent_inode, name, child_ino):
                    return

    raise XFSError(f"Cannot add directory entry '{name}' — directory full or unsupported format")


def _remove_dir_entry(f, part_offset, sb, parent_ino, name):
    """Remove a directory entry, handling all formats."""
    parent_inode = read_inode(f, part_offset, sb, parent_ino)
    if parent_inode is None:
        raise XFSCorruptionError(f"Cannot read parent inode {parent_ino}")

    fmt = parent_inode['di_format']

    if fmt == XFS_DINODE_FMT_LOCAL:
        if remove_entry_sf(parent_inode, sb, name):
            write_inode(f, part_offset, sb, parent_ino, parent_inode)
            return

    elif fmt in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
        extents = get_extents(f, part_offset, sb, parent_inode)
        if extents:
            from pyirix.xfs.ondisk import fsblock_to_offset
            import struct

            startoff, startblock, blockcount = extents[0]
            disk_off = fsblock_to_offset(sb, part_offset, startblock)
            f.seek(disk_off)
            header = f.read(16)

            magic2 = struct.unpack('>H', header[8:10])[0]
            magic4 = struct.unpack('>I', header[0:4])[0]

            if magic2 == XFS_DIR_LEAF_MAGIC:
                if remove_entry_v1_leaf(f, part_offset, sb, parent_inode, name):
                    return
            elif magic4 == XFS_DIR2_BLOCK_MAGIC:
                if remove_entry_dir2_block(f, part_offset, sb, parent_inode, name):
                    return

    raise XFSPathError(f"Entry '{name}' not found in parent directory")


# ── Formatting Helpers ──────────────────────────────────────────────

def _type_char(ft):
    """Get single character for file type."""
    return {
        S_IFDIR: 'd', S_IFREG: '-', S_IFLNK: 'l',
        S_IFCHR: 'c', S_IFBLK: 'b', S_IFIFO: 'p',
    }.get(ft, '?')


def _format_perms(mode):
    """Format permission bits as rwxrwxrwx string."""
    chars = ''
    for i in range(3):
        shift = (2 - i) * 3
        val = (mode >> shift) & 7
        chars += 'r' if val & 4 else '-'
        chars += 'w' if val & 2 else '-'
        chars += 'x' if val & 1 else '-'
    return chars
