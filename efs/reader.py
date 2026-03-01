#!/usr/bin/env python3
"""Read and extract files from SGI EFS disk images.

SGI disk images contain a volume header (sector 0) with a partition table.
The EFS filesystem lives in the partition with type 7 (EFS) or 5 (sysv).
This tool parses the volume header to find the EFS partition, then reads
the EFS superblock, inodes, and directory entries to list or extract files.

Uses the CORRECT SGI EFS on-disk format:
  - Extent: byte[0]=magic, bytes[1:3]=bn(BE), byte[4]=length, bytes[5:7]=offset(BE)
  - Directory blocks: 0xBEEF magic, slot-based, entries packed from bottom

Usage:
    python3 tools/efs_reader.py list <disk_image>
    python3 tools/efs_reader.py extract <disk_image> <output_dir> [--path dist]
    python3 tools/efs_reader.py info <disk_image>
"""

import argparse
import os
import struct
import sys
from pathlib import Path

# ── SGI Volume Header constants ──────────────────────────────────────

VHMAGIC = 0x0BE5A941
NVDIR = 15
NPARTAB = 16
SECTOR_SIZE = 512
VH_SIZE = 512

# Partition types
PTYPE_VOLHDR = 0
PTYPE_RAW = 3
PTYPE_SYSV = 5
PTYPE_VOLUME = 6
PTYPE_EFS = 7
PTYPE_XFS = 10

# ── EFS constants ────────────────────────────────────────────────────

EFS_MAGIC = 0x072959
EFS_MAGIC_NEW = 0x07295A
EFS_BLOCK_SIZE = 512
EFS_INOPBB = 4           # inodes per basic block (512 / 128)
EFS_INODE_SIZE = 128
EFS_ROOT_INODE = 2
EFS_MAX_EXTENTS = 12
EFS_DIRBLK_MAGIC = 0xBEEF

# File type constants
S_IFMT  = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFCHR = 0o020000
S_IFBLK = 0o060000
S_IFIFO = 0o010000


def read_vh(f):
    """Read and parse an SGI volume header from file position 0."""
    f.seek(0)
    data = f.read(VH_SIZE)
    if len(data) < VH_SIZE:
        return None

    magic = struct.unpack('>I', data[0:4])[0]
    if magic != VHMAGIC:
        return None

    vh = {'magic': magic}
    vh['bootfile'] = data[8:24].split(b'\x00')[0].decode('ascii', errors='replace')

    # Device parameters at offset 24, size 48
    dp_offset = 24
    dp_size = 48

    # Volume directory: 15 entries, each 16 bytes
    vd_offset = dp_offset + dp_size
    vh['vd'] = []
    for i in range(NVDIR):
        off = vd_offset + i * 16
        name = data[off:off+8].split(b'\x00')[0].decode('ascii', errors='replace')
        lbn, nbytes = struct.unpack('>ii', data[off+8:off+16])
        vh['vd'].append({'name': name, 'lbn': lbn, 'nbytes': nbytes})

    # Partition table: 16 entries, each 12 bytes
    pt_offset = vd_offset + NVDIR * 16
    vh['pt'] = []
    for i in range(NPARTAB):
        off = pt_offset + i * 12
        nblks, firstlbn, ptype = struct.unpack('>iii', data[off:off+12])
        vh['pt'].append({'nblks': nblks, 'firstlbn': firstlbn, 'type': ptype})

    return vh


def find_efs_partition(f):
    """Find the EFS partition in a disk image.

    Returns (partition_byte_offset, partition_size_bytes) or None.
    Searches for partition type 7 (EFS) or 5 (sysv), matching efsextract.
    """
    vh = read_vh(f)
    if vh:
        # Look for EFS (type 7) or sysv (type 5) partition
        for i, pt in enumerate(vh['pt']):
            if pt['type'] in (PTYPE_EFS, PTYPE_SYSV) and pt['nblks'] > 0:
                offset = pt['firstlbn'] * SECTOR_SIZE
                size = pt['nblks'] * SECTOR_SIZE
                return offset, size
        return None

    # No volume header — check if it's a raw EFS image
    f.seek(EFS_BLOCK_SIZE)
    sb_data = f.read(EFS_BLOCK_SIZE)
    if len(sb_data) >= 32:
        magic = struct.unpack('>I', sb_data[28:32])[0]
        if magic in (EFS_MAGIC, EFS_MAGIC_NEW):
            f.seek(0, 2)
            size = f.tell()
            return 0, size

    return None


def read_superblock(f, part_offset):
    """Read and parse the EFS superblock at block 1 within the partition."""
    f.seek(part_offset + EFS_BLOCK_SIZE)
    sb_data = f.read(EFS_BLOCK_SIZE)

    sb = {}
    sb['fs_size'] = struct.unpack('>i', sb_data[0:4])[0]
    sb['fs_firstcg'] = struct.unpack('>i', sb_data[4:8])[0]
    sb['fs_cgfsize'] = struct.unpack('>i', sb_data[8:12])[0]
    sb['fs_cgisize'] = struct.unpack('>h', sb_data[12:14])[0]
    sb['fs_sectors'] = struct.unpack('>h', sb_data[14:16])[0]
    sb['fs_heads'] = struct.unpack('>h', sb_data[16:18])[0]
    sb['fs_ncg'] = struct.unpack('>h', sb_data[18:20])[0]
    sb['fs_dirty'] = struct.unpack('>h', sb_data[20:22])[0]
    sb['fs_time'] = struct.unpack('>i', sb_data[24:28])[0]
    sb['fs_magic'] = struct.unpack('>I', sb_data[28:32])[0]
    sb['fs_fname'] = sb_data[32:38].rstrip(b'\x00').decode('ascii', errors='replace')
    sb['fs_fpack'] = sb_data[38:44].rstrip(b'\x00').decode('ascii', errors='replace')
    sb['fs_bmsize'] = struct.unpack('>i', sb_data[44:48])[0]
    sb['fs_tfree'] = struct.unpack('>i', sb_data[48:52])[0]
    sb['fs_tinode'] = struct.unpack('>i', sb_data[52:56])[0]
    sb['fs_bmblock'] = struct.unpack('>i', sb_data[56:60])[0]
    sb['fs_replsb'] = struct.unpack('>i', sb_data[60:64])[0]

    if sb['fs_magic'] not in (EFS_MAGIC, EFS_MAGIC_NEW):
        return None

    return sb


def parse_extent(data):
    """Parse an 8-byte EFS extent descriptor (correct SGI format).

    On-disk layout (8 bytes, big-endian):
      byte[0]   = ex_magic  (8 bits)
      byte[1:3] = ex_bn     (24 bits, big-endian)
      byte[4]   = ex_length (8 bits)
      byte[5:7] = ex_offset (24 bits, big-endian)

    As two 32-bit BE words:
      word1 = (ex_magic << 24) | ex_bn
      word2 = (ex_length << 24) | ex_offset
    """
    word1, word2 = struct.unpack('>II', data[:8])
    return {
        'magic': (word1 >> 24) & 0xFF,
        'bn': word1 & 0xFFFFFF,
        'length': (word2 >> 24) & 0xFF,
        'offset': word2 & 0xFFFFFF,
    }


def inode_to_bb(sb, ino):
    """Convert inode number to basic block number (matching EFS_ITOBB macro)."""
    ipcg = sb['fs_cgisize'] * EFS_INOPBB  # inodes per cylinder group
    cg = ino // ipcg                       # cylinder group number
    cgbb = (ino >> 2) % sb['fs_cgisize']   # bb within cg (INOPBBSHIFT=2)
    return sb['fs_firstcg'] + cg * sb['fs_cgfsize'] + cgbb


def read_inode(f, part_offset, sb, ino):
    """Read a single inode by number."""
    bb = inode_to_bb(sb, ino)
    slot = ino & 0x3  # EFS_INOPBBMASK = 3

    f.seek(part_offset + bb * EFS_BLOCK_SIZE)
    block_data = f.read(EFS_BLOCK_SIZE)

    inode_data = block_data[slot * EFS_INODE_SIZE:(slot + 1) * EFS_INODE_SIZE]
    if len(inode_data) < EFS_INODE_SIZE:
        return None

    mode = struct.unpack('>H', inode_data[0:2])[0]
    if mode == 0:
        return None

    nlink = struct.unpack('>h', inode_data[2:4])[0]
    uid = struct.unpack('>H', inode_data[4:6])[0]
    gid = struct.unpack('>H', inode_data[6:8])[0]
    size = struct.unpack('>i', inode_data[8:12])[0]
    atime = struct.unpack('>i', inode_data[12:16])[0]
    mtime = struct.unpack('>i', inode_data[16:20])[0]
    ctime = struct.unpack('>i', inode_data[20:24])[0]
    gen = struct.unpack('>I', inode_data[24:28])[0]
    numextents = struct.unpack('>h', inode_data[28:30])[0]
    version = inode_data[30]

    extents = []
    for i in range(min(numextents, EFS_MAX_EXTENTS)):
        ext_offset = 32 + i * 8
        if ext_offset + 8 <= len(inode_data):
            ext = parse_extent(inode_data[ext_offset:ext_offset + 8])
            extents.append(ext)

    return {
        'mode': mode,
        'nlink': nlink,
        'uid': uid,
        'gid': gid,
        'size': size,
        'atime': atime,
        'mtime': mtime,
        'ctime': ctime,
        'gen': gen,
        'numextents': numextents,
        'version': version,
        'extents': extents,
    }


def get_all_extents(f, part_offset, inode):
    """Get all extents for an inode, handling indirect extents."""
    numextents = inode['numextents']
    if numextents <= EFS_MAX_EXTENTS:
        return inode['extents'][:numextents]

    # Indirect extents: the direct extents point to blocks containing
    # the actual extent table
    num_indirect = inode['extents'][0]['offset'] if inode['extents'] else 0
    if num_indirect > EFS_MAX_EXTENTS:
        return inode['extents']

    # Read indirect extent blocks
    indirect_data = bytearray()
    for i in range(min(num_indirect, len(inode['extents']))):
        ext = inode['extents'][i]
        f.seek(part_offset + ext['bn'] * EFS_BLOCK_SIZE)
        indirect_data.extend(f.read(ext['length'] * EFS_BLOCK_SIZE))

    # Parse the actual extents from the indirect data
    all_extents = []
    for i in range(numextents):
        off = i * 8
        if off + 8 <= len(indirect_data):
            all_extents.append(parse_extent(indirect_data[off:off + 8]))

    return all_extents


def read_dir_entries(f, part_offset, sb, inode):
    """Read directory entries from an inode using 0xBEEF slot-based format."""
    entries = []
    extents = get_all_extents(f, part_offset, inode)

    for ext in extents:
        f.seek(part_offset + ext['bn'] * EFS_BLOCK_SIZE)
        ext_data = f.read(ext['length'] * EFS_BLOCK_SIZE)

        # Process each 512-byte directory block within the extent
        for blk_off in range(0, len(ext_data), EFS_BLOCK_SIZE):
            dirblk = ext_data[blk_off:blk_off + EFS_BLOCK_SIZE]
            if len(dirblk) < EFS_BLOCK_SIZE:
                break

            # Check magic
            magic = struct.unpack('>H', dirblk[0:2])[0]
            if magic != EFS_DIRBLK_MAGIC:
                continue

            firstused = dirblk[2]
            slots = dirblk[3]

            # Slot table starts at byte 4 (after the 4-byte header)
            for slot in range(slots):
                slot_val = dirblk[4 + slot]
                if slot_val < firstused:
                    continue  # unused slot

                # Entry is at slot_val * 2 bytes from start of dirblk
                entry_off = slot_val * 2
                if entry_off + 5 > EFS_BLOCK_SIZE:
                    continue

                ino = struct.unpack('>I', dirblk[entry_off:entry_off + 4])[0]
                namelen = dirblk[entry_off + 4]
                if entry_off + 5 + namelen > EFS_BLOCK_SIZE:
                    continue

                name = dirblk[entry_off + 5:entry_off + 5 + namelen].decode(
                    'ascii', errors='replace')

                if name not in ('.', '..'):
                    entries.append((name, ino))

    return entries


def read_file_data(f, part_offset, sb, inode):
    """Read file data by following the extent chain."""
    if inode['size'] == 0:
        return b''

    extents = get_all_extents(f, part_offset, inode)

    # Sort by offset to ensure correct order
    extents.sort(key=lambda e: e['offset'])

    chunks = []
    for ext in extents:
        f.seek(part_offset + ext['bn'] * EFS_BLOCK_SIZE)
        data = f.read(ext['length'] * EFS_BLOCK_SIZE)
        chunks.append(data)

    if not chunks:
        return b''

    full_data = b''.join(chunks)
    return full_data[:inode['size']]


def read_symlink_target(f, part_offset, sb, inode):
    """Read symlink target — stored as raw path in extent data blocks."""
    data = read_file_data(f, part_offset, sb, inode)
    return data.rstrip(b'\x00').decode('ascii', errors='replace')


def format_perms(mode):
    """Format permission bits as rwxrwxrwx string."""
    chars = ''
    for i in range(3):
        shift = (2 - i) * 3
        val = (mode >> shift) & 7
        chars += 'r' if val & 4 else '-'
        chars += 'w' if val & 2 else '-'
        chars += 'x' if val & 1 else '-'
    return chars


def format_type(mode):
    """Get single character for file type."""
    ft = mode & S_IFMT
    return {
        S_IFDIR: 'd', S_IFREG: '-', S_IFLNK: 'l',
        S_IFCHR: 'c', S_IFBLK: 'b', S_IFIFO: 'p',
    }.get(ft, '?')


# ── Recursive operations ──────────────────────────────────────────────

def list_recursive(f, part_offset, sb, inode_num, path, path_filter=None):
    """Recursively list directory contents."""
    inode = read_inode(f, part_offset, sb, inode_num)
    if not inode:
        return

    mode = inode['mode']
    ft = format_type(mode)
    perms = format_perms(mode)

    # Apply path filter
    show = True
    if path_filter:
        stripped = path.lstrip('/')
        filt = path_filter.lstrip('/')
        show = (stripped == filt or stripped.startswith(filt + '/') or
                path == '/')

    if show and path != '/':
        suffix = ''
        if ft == 'l':
            target = read_symlink_target(f, part_offset, sb, inode)
            suffix = f' -> {target}'
        print(f"{ft}{perms} {inode['uid']:5d} {inode['gid']:5d} "
              f"{inode['size']:10d} {path}{suffix}")

    if mode & S_IFMT == S_IFDIR:
        entries = read_dir_entries(f, part_offset, sb, inode)
        for name, ino in sorted(entries):
            child_path = path.rstrip('/') + '/' + name
            list_recursive(f, part_offset, sb, ino, child_path, path_filter)


def count_files(f, part_offset, sb, inode_num, path, path_filter=None):
    """Count files recursively. Returns (files, dirs, symlinks, total_bytes)."""
    inode = read_inode(f, part_offset, sb, inode_num)
    if not inode:
        return 0, 0, 0, 0

    mode = inode['mode']
    ft = mode & S_IFMT
    files = dirs = symlinks = total_bytes = 0

    in_scope = True
    if path_filter:
        stripped = path.lstrip('/')
        filt = path_filter.lstrip('/')
        in_scope = (stripped == filt or stripped.startswith(filt + '/') or
                    filt.startswith(stripped + '/') or path == '/')

    if ft == S_IFDIR:
        if in_scope and path != '/':
            dirs += 1
        entries = read_dir_entries(f, part_offset, sb, inode)
        for name, ino in entries:
            child_path = path.rstrip('/') + '/' + name
            f2, d2, s2, b2 = count_files(f, part_offset, sb, ino,
                                          child_path, path_filter)
            files += f2
            dirs += d2
            symlinks += s2
            total_bytes += b2
    elif in_scope:
        if ft == S_IFLNK:
            symlinks += 1
        elif ft == S_IFREG:
            files += 1
            total_bytes += inode['size']

    return files, dirs, symlinks, total_bytes


def extract_recursive(f, part_offset, sb, inode_num, path,
                      dest_dir, path_filter=None, stats=None):
    """Recursively extract files from an EFS filesystem."""
    if stats is None:
        stats = {'files': 0, 'dirs': 0, 'symlinks': 0, 'errors': 0}

    inode = read_inode(f, part_offset, sb, inode_num)
    if not inode:
        return stats

    mode = inode['mode']
    ft = mode & S_IFMT

    # Path filter logic
    in_scope = True
    if path_filter:
        stripped = path.lstrip('/')
        filter_prefix = path_filter.lstrip('/')
        in_scope = (stripped == filter_prefix or
                    stripped.startswith(filter_prefix + '/') or
                    filter_prefix.startswith(stripped + '/') or
                    path == '/')

    if ft == S_IFDIR:
        entries = read_dir_entries(f, part_offset, sb, inode)

        if in_scope and path != '/':
            if path_filter:
                filter_prefix = path_filter.lstrip('/')
                stripped = path.lstrip('/')
                if stripped.startswith(filter_prefix):
                    rel = stripped[len(filter_prefix):].lstrip('/')
                else:
                    rel = stripped
            else:
                rel = path.lstrip('/')

            if rel:
                host_dir = os.path.join(dest_dir, rel)
                os.makedirs(host_dir, exist_ok=True)
                stats['dirs'] += 1

        for name, ino in entries:
            child_path = path.rstrip('/') + '/' + name
            extract_recursive(f, part_offset, sb, ino, child_path,
                              dest_dir, path_filter, stats)

    elif in_scope:
        if path_filter:
            filter_prefix = path_filter.lstrip('/')
            stripped = path.lstrip('/')
            if stripped.startswith(filter_prefix + '/'):
                rel = stripped[len(filter_prefix) + 1:]
            elif stripped.startswith(filter_prefix):
                rel = stripped[len(filter_prefix):].lstrip('/')
            else:
                rel = stripped
        else:
            rel = path.lstrip('/')

        if not rel:
            return stats

        host_path = os.path.join(dest_dir, rel)
        os.makedirs(os.path.dirname(host_path), exist_ok=True)

        if ft == S_IFLNK:
            try:
                target = read_symlink_target(f, part_offset, sb, inode)
                if os.path.lexists(host_path):
                    os.unlink(host_path)
                os.symlink(target, host_path)
                stats['symlinks'] += 1
            except Exception as e:
                print(f"  Error creating symlink {rel}: {e}", file=sys.stderr)
                stats['errors'] += 1

        elif ft == S_IFREG:
            try:
                data = read_file_data(f, part_offset, sb, inode)
                with open(host_path, 'wb') as out:
                    out.write(data)
                stats['files'] += 1
            except Exception as e:
                print(f"  Error extracting {rel}: {e}", file=sys.stderr)
                stats['errors'] += 1

    return stats


# ── CLI commands ─────────────────────────────────────────────────────

def cmd_info(args):
    """Show volume header and EFS superblock info."""
    with open(args.image, 'rb') as f:
        vh = read_vh(f)
        if vh:
            print(f"SGI Volume Header: {args.image}")
            print(f"  Magic: 0x{vh['magic']:08x}")
            print(f"  Boot file: \"{vh['bootfile']}\"")
            print()

            print("Volume Directory:")
            for i, vd in enumerate(vh['vd']):
                if vd['name']:
                    print(f"  [{i:2d}] \"{vd['name']}\" lbn={vd['lbn']} "
                          f"size={vd['nbytes']} ({vd['nbytes']//1024}KB)")

            print()
            ptype_names = {0: 'volhdr', 3: 'raw', 5: 'sysv', 6: 'volume',
                           7: 'efs', 10: 'xfs'}
            print("Partition Table:")
            for i, pt in enumerate(vh['pt']):
                if pt['nblks'] > 0:
                    tname = ptype_names.get(pt['type'], str(pt['type']))
                    size_mb = pt['nblks'] * SECTOR_SIZE / (1024 * 1024)
                    print(f"  [{i:2d}] type={tname:8s} start={pt['firstlbn']} "
                          f"blocks={pt['nblks']} ({size_mb:.1f}MB)")
        else:
            print(f"No SGI volume header found in {args.image}")

        print()
        result = find_efs_partition(f)
        if result:
            part_offset, part_size = result
            print(f"EFS partition at offset {part_offset} ({part_offset // 1024}KB), "
                  f"size {part_size} ({part_size // (1024*1024)}MB)")

            sb = read_superblock(f, part_offset)
            if sb:
                print(f"  Magic: 0x{sb['fs_magic']:06x}")
                print(f"  Size: {sb['fs_size']} blocks "
                      f"({sb['fs_size'] * EFS_BLOCK_SIZE // (1024*1024)}MB)")
                print(f"  Cylinder groups: {sb['fs_ncg']}")
                print(f"  CG size: {sb['fs_cgfsize']} blocks")
                print(f"  Inodes per CG: {sb['fs_cgisize']} (bb)")
                print(f"  Total inodes: {sb['fs_ncg'] * sb['fs_cgisize'] * EFS_INOPBB}")
                print(f"  First CG: block {sb['fs_firstcg']}")
                print(f"  Free blocks: {sb['fs_tfree']}")
                print(f"  Free inodes: {sb['fs_tinode']}")
                print(f"  Volume name: {sb['fs_fname']}")

                # Count files
                files, dirs, symlinks, total = count_files(
                    f, part_offset, sb, EFS_ROOT_INODE, '/')
                print(f"\n  Files: {files}, Dirs: {dirs}, "
                      f"Symlinks: {symlinks}, Total: {total // 1024}KB")
            else:
                print("  ERROR: Could not read EFS superblock")
        else:
            print("No EFS partition found")


def cmd_list(args):
    """List contents of EFS filesystem in disk image."""
    with open(args.image, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print(f"Error: No EFS partition found in {args.image}",
                  file=sys.stderr)
            return 1

        part_offset, part_size = result
        sb = read_superblock(f, part_offset)
        if not sb:
            print("Error: Invalid EFS superblock", file=sys.stderr)
            return 1

        path_filter = args.path if hasattr(args, 'path') and args.path else None
        list_recursive(f, part_offset, sb, EFS_ROOT_INODE, '/', path_filter)

    return 0


def cmd_extract(args):
    """Extract files from EFS filesystem."""
    with open(args.image, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print(f"Error: No EFS partition found in {args.image}",
                  file=sys.stderr)
            return 1

        part_offset, part_size = result
        sb = read_superblock(f, part_offset)
        if not sb:
            print("Error: Invalid EFS superblock", file=sys.stderr)
            return 1

        print(f"Reading from {args.image}...")
        print(f"  EFS at offset {part_offset}, "
              f"size {part_size // (1024*1024)}MB")

        dest = args.output
        os.makedirs(dest, exist_ok=True)

        path_filter = args.path if hasattr(args, 'path') and args.path else None
        if path_filter:
            print(f"  Extracting path: /{path_filter}")
        print(f"  Extracting to: {dest}")

        stats = extract_recursive(f, part_offset, sb, EFS_ROOT_INODE,
                                  '/', dest, path_filter)

        print(f"\nExtraction complete:")
        print(f"  Files:    {stats['files']}")
        print(f"  Dirs:     {stats['dirs']}")
        print(f"  Symlinks: {stats['symlinks']}")
        if stats['errors']:
            print(f"  Errors:   {stats['errors']}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Read and extract files from SGI EFS disk images"
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # info command
    info_p = subparsers.add_parser('info', help='Show volume header and EFS info')
    info_p.add_argument('image', help='Disk image path')

    # list command
    list_p = subparsers.add_parser('list', help='List EFS filesystem contents')
    list_p.add_argument('image', help='Disk image path')
    list_p.add_argument('--path', help='Only list paths under this prefix')

    # extract command
    ext_p = subparsers.add_parser('extract', help='Extract files from EFS')
    ext_p.add_argument('image', help='Disk image path')
    ext_p.add_argument('output', help='Output directory')
    ext_p.add_argument('--path', help='Only extract paths under this prefix '
                       '(e.g. "dist" to extract only dist/)')

    args = parser.parse_args()

    if args.command == 'info':
        return cmd_info(args)
    elif args.command == 'list':
        return cmd_list(args)
    elif args.command == 'extract':
        return cmd_extract(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)
