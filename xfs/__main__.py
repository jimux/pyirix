"""CLI for pyirix.xfs: info, ls, cat, extract, inject, mkdir, rm, check.

Usage: python3 -m pyirix.xfs <command> <image> [options]
"""

import argparse
import os
import sys

from pyirix.xfs.constants import (
    XFS_SB_MAGIC, S_IFMT, S_IFDIR, S_IFREG, S_IFLNK,
    XFSError,
)
from pyirix.xfs.image import open_disk_image, find_xfs_partition
from pyirix.xfs.superblock import read_superblock, sash_compatible
from pyirix.xfs.inode import read_inode, read_file_data, read_symlink
from pyirix.xfs.directory import read_dir_entries
from pyirix.xfs.operations import (
    resolve_path, list_dir, list_recursive, extract_recursive,
    create_file, write_file, delete_file, mkdir, rmdir,
    _format_perms, _type_char,
)


def cmd_info(args):
    """Show filesystem info."""
    with open_disk_image(args.image) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        print(f"XFS Filesystem: {args.image}")
        print(f"  Block size:     {sb['sb_blocksize']}")
        print(f"  Total blocks:   {sb['sb_dblocks']}")
        print(f"  Free blocks:    {sb['sb_fdblocks']}")
        print(f"  AG count:       {sb['sb_agcount']}")
        print(f"  AG blocks:      {sb['sb_agblocks']}")
        print(f"  Inode size:     {sb['sb_inodesize']}")
        print(f"  Root inode:     {sb['sb_rootino']}")
        print(f"  Inodes alloc:   {sb['sb_icount']}")
        print(f"  Inodes free:    {sb['sb_ifree']}")
        print(f"  Version:        0x{sb['sb_versionnum']:04x}")
        print(f"  Volume name:    {sb['sb_fname']}")

        ok, reason = sash_compatible(sb)
        print(f"  SASH compat:    {'Yes' if ok else 'No'} — {reason}")

    return 0


def cmd_ls(args):
    """List directory contents."""
    with open_disk_image(args.image) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        path = args.path or '/'

        if args.recursive:
            ino = resolve_path(f, part_offset, sb, path)
            if ino is None:
                print(f"Error: Path not found: {path}", file=sys.stderr)
                return 1
            results = []
            list_recursive(f, part_offset, sb, ino, path, results,
                           max_entries=args.max_entries)
            for entry in results:
                suffix = ''
                if entry.get('link_target'):
                    suffix = f" -> {entry['link_target']}"
                print(f"{entry['type']}{entry['perms']} {entry['uid']:5d} "
                      f"{entry['gid']:5d} {entry['size']:10d} {entry['path']}{suffix}")
        else:
            try:
                entries = list_dir(f, part_offset, sb, path)
            except XFSError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1

            for entry in entries:
                suffix = ''
                if entry.get('link_target'):
                    suffix = f" -> {entry['link_target']}"
                perms = _format_perms(entry['mode'])
                print(f"{entry['type']}{perms} {entry['uid']:5d} "
                      f"{entry['gid']:5d} {entry['size']:10d} {entry['name']}{suffix}")

    return 0


def cmd_cat(args):
    """Print file contents."""
    with open_disk_image(args.image) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        ino = resolve_path(f, part_offset, sb, args.path)
        if ino is None:
            print(f"Error: Path not found: {args.path}", file=sys.stderr)
            return 1

        inode = read_inode(f, part_offset, sb, ino)
        if inode is None:
            print(f"Error: Cannot read inode", file=sys.stderr)
            return 1

        ft = inode['di_mode'] & S_IFMT
        if ft != S_IFREG:
            print(f"Error: Not a regular file", file=sys.stderr)
            return 1

        data = read_file_data(f, part_offset, sb, inode)

        if args.binary:
            sys.stdout.buffer.write(data)
        else:
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                text = data.decode('latin-1')
            sys.stdout.write(text)

    return 0


def cmd_extract(args):
    """Extract files to host filesystem."""
    dest = args.dest or '.'

    with open_disk_image(args.image) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        path = args.path or '/'
        ino = resolve_path(f, part_offset, sb, path)
        if ino is None:
            print(f"Error: Path not found: {path}", file=sys.stderr)
            return 1

        stats = extract_recursive(f, part_offset, sb, ino, path, dest)
        print(f"Extracted: {stats['files']} files, {stats['dirs']} dirs, "
              f"{stats['symlinks']} symlinks, {stats['errors']} errors")

    return 0


def cmd_inject(args):
    """Inject a file into the XFS filesystem."""
    host_path = args.host_path
    guest_path = args.guest_path

    if not os.path.exists(host_path):
        print(f"Error: Host file not found: {host_path}", file=sys.stderr)
        return 1

    with open(host_path, 'rb') as hf:
        data = hf.read()

    with open_disk_image(args.image, writable=True) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        try:
            # Check if file exists — overwrite if so, create if not
            existing = resolve_path(f, part_offset, sb, guest_path)
            if existing is not None:
                write_file(f, part_offset, sb, guest_path, data)
                print(f"Overwrote {guest_path} ({len(data)} bytes)")
            else:
                mode = args.mode if args.mode else 0o644
                ino = create_file(f, part_offset, sb, guest_path, data,
                                  mode=mode, uid=args.uid, gid=args.gid)
                print(f"Created {guest_path} (inode {ino}, {len(data)} bytes)")
        except XFSError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_mkdir(args):
    """Create a directory."""
    with open_disk_image(args.image, writable=True) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        try:
            mode = args.mode if args.mode else 0o755
            ino = mkdir(f, part_offset, sb, args.path, mode=mode,
                        uid=args.uid, gid=args.gid)
            print(f"Created directory {args.path} (inode {ino})")
        except XFSError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_rm(args):
    """Remove a file or empty directory."""
    with open_disk_image(args.image, writable=True) as f:
        part = find_xfs_partition(f)
        if not part:
            print("Error: No XFS partition found", file=sys.stderr)
            return 1

        part_offset, part_size = part
        sb = read_superblock(f, part_offset)
        if sb is None:
            print("Error: Cannot read XFS superblock", file=sys.stderr)
            return 1

        try:
            ino = resolve_path(f, part_offset, sb, args.path)
            if ino is None:
                print(f"Error: Path not found: {args.path}", file=sys.stderr)
                return 1

            inode = read_inode(f, part_offset, sb, ino)
            if inode is None:
                print(f"Error: Cannot read inode", file=sys.stderr)
                return 1

            ft = inode['di_mode'] & S_IFMT
            if ft == S_IFDIR:
                rmdir(f, part_offset, sb, args.path)
                print(f"Removed directory {args.path}")
            else:
                delete_file(f, part_offset, sb, args.path)
                print(f"Removed {args.path}")
        except XFSError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_check(args):
    """Run filesystem consistency checks."""
    with open_disk_image(args.image) as f:
        part = find_xfs_partition(f)
        results = []

        if not part:
            results.append(('FAIL', 'XFS partition not found'))
            _print_results(results)
            return 1

        part_offset, part_size = part
        results.append(('PASS', f'XFS partition at offset {part_offset}'))

        sb = read_superblock(f, part_offset)
        if sb is None:
            results.append(('FAIL', 'Cannot read superblock'))
            _print_results(results)
            return 1

        results.append(('PASS', f'Superblock magic OK (0x{sb["sb_magicnum"]:08x})'))

        ok, reason = sash_compatible(sb)
        results.append(('PASS' if ok else 'WARN', f'SASH compat: {reason}'))

        # Check root inode
        root = read_inode(f, part_offset, sb, sb['sb_rootino'])
        if root is None:
            results.append(('FAIL', f'Cannot read root inode {sb["sb_rootino"]}'))
        else:
            results.append(('PASS', f'Root inode {sb["sb_rootino"]} readable'))
            if (root['di_mode'] & S_IFMT) != S_IFDIR:
                results.append(('FAIL', 'Root inode is not a directory'))
            else:
                entries = read_dir_entries(f, part_offset, sb, root)
                results.append(('PASS', f'Root directory has {len(entries)} entries'))

        # Path probes
        for probe_path in ['/unix', '/unix.new', '/stand', '/sash']:
            ino = resolve_path(f, part_offset, sb, probe_path)
            if ino is not None:
                inode = read_inode(f, part_offset, sb, ino)
                if inode:
                    size = inode['di_size']
                    results.append(('INFO', f'{probe_path}: inode {ino}, {size} bytes'))
                else:
                    results.append(('INFO', f'{probe_path}: inode {ino} (unreadable)'))
            else:
                results.append(('INFO', f'{probe_path}: not found'))

        _print_results(results)

    return 0


def _print_results(results):
    """Print check results."""
    for status, msg in results:
        if status == 'PASS':
            marker = '[PASS]'
        elif status == 'FAIL':
            marker = '[FAIL]'
        elif status == 'WARN':
            marker = '[WARN]'
        else:
            marker = '[INFO]'
        print(f"  {marker} {msg}")


def cmd_mkfs(args):
    """Create an IRIX V1-directory XFS image from scratch."""
    from pyirix.xfs.mkfs import mkfs_xfs
    mkfs_xfs(args.image, size_mb=args.size_mb, agcount=args.agcount,
             with_volume_header=not args.raw, label=args.label or "")
    import os
    print(f"Created {args.image} ({os.path.getsize(args.image)} bytes): "
          f"{args.size_mb}MB, {args.agcount} AG(s), "
          f"{'raw partition' if args.raw else 'with SGI volume header'}")
    return 0


def cmd_repair(args):
    """Diagnose and optionally repair an XFS image."""
    from pyirix.xfs.repair import check_xfs, repair_xfs
    with open_disk_image(args.image, writable=args.fix) as f:
        part = find_xfs_partition(f)
        part_offset = part[0] if part else 0   # raw image -> offset 0
        if not args.fix:
            report = check_xfs(f, part_offset)
            for finding in report:
                print(f"  [{finding.level}] {finding.code}: {finding.msg}")
            print(f"\n{report.summary()} — "
                  f"{'OK' if report.ok else ('REPAIRABLE' if report.repairable else 'UNREPAIRABLE')}")
            return 0 if report.ok else 1
        report, actions = repair_xfs(f, part_offset, dry_run=False)
        for finding in report:
            print(f"  [{finding.level}] {finding.code}: {finding.msg}")
        for name, result in actions:
            mark = 'fixed' if result.get('changed') else 'no-op'
            print(f"  -> {name} [{mark}]: {result['reason']}")
        after = check_xfs(f, part_offset)
        print(f"\nafter repair: {after.summary()} — {'OK' if after.ok else 'still failing'}")
        return 0 if after.ok else 1


def main():
    parser = argparse.ArgumentParser(
        prog='python3 -m pyirix.xfs',
        description='XFS filesystem tools for SGI disk images')

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # info
    p_info = subparsers.add_parser('info', help='Show filesystem info')
    p_info.add_argument('image', help='Disk image path')

    # ls
    p_ls = subparsers.add_parser('ls', help='List directory')
    p_ls.add_argument('image', help='Disk image path')
    p_ls.add_argument('path', nargs='?', default='/', help='Path to list')
    p_ls.add_argument('-r', '--recursive', action='store_true')
    p_ls.add_argument('-n', '--max-entries', type=int, default=5000)

    # cat
    p_cat = subparsers.add_parser('cat', help='Print file contents')
    p_cat.add_argument('image', help='Disk image path')
    p_cat.add_argument('path', help='Path to file')
    p_cat.add_argument('-b', '--binary', action='store_true',
                       help='Output raw binary')

    # extract
    p_extract = subparsers.add_parser('extract', help='Extract files')
    p_extract.add_argument('image', help='Disk image path')
    p_extract.add_argument('path', nargs='?', default='/',
                           help='Path to extract')
    p_extract.add_argument('-d', '--dest', default='.', help='Destination dir')

    # inject
    p_inject = subparsers.add_parser('inject', help='Inject file into image')
    p_inject.add_argument('image', help='Disk image path')
    p_inject.add_argument('host_path', help='Source file on host')
    p_inject.add_argument('guest_path', help='Destination path in image')
    p_inject.add_argument('--mode', type=lambda x: int(x, 8), default=None,
                          help='File mode (octal, e.g. 755)')
    p_inject.add_argument('--uid', type=int, default=0)
    p_inject.add_argument('--gid', type=int, default=0)

    # mkdir
    p_mkdir = subparsers.add_parser('mkdir', help='Create directory')
    p_mkdir.add_argument('image', help='Disk image path')
    p_mkdir.add_argument('path', help='Directory path')
    p_mkdir.add_argument('--mode', type=lambda x: int(x, 8), default=None)
    p_mkdir.add_argument('--uid', type=int, default=0)
    p_mkdir.add_argument('--gid', type=int, default=0)

    # rm
    p_rm = subparsers.add_parser('rm', help='Remove file or empty directory')
    p_rm.add_argument('image', help='Disk image path')
    p_rm.add_argument('path', help='Path to remove')

    # check
    p_check = subparsers.add_parser('check', help='Filesystem check')
    p_check.add_argument('image', help='Disk image path')

    # mkfs
    p_mkfs = subparsers.add_parser('mkfs', help='Create an IRIX V1 XFS image')
    p_mkfs.add_argument('image', help='Output image path')
    p_mkfs.add_argument('--size-mb', type=int, default=16, help='Filesystem size (MB)')
    p_mkfs.add_argument('--agcount', type=int, default=1, help='Allocation groups')
    p_mkfs.add_argument('--label', default='', help='Volume label (<=6 chars)')
    p_mkfs.add_argument('--raw', action='store_true',
                        help='Write a raw partition (no SGI volume header)')

    # repair
    p_repair = subparsers.add_parser('repair',
                                     help='Diagnose (and with --fix, repair) an image')
    p_repair.add_argument('image', help='Disk image path')
    p_repair.add_argument('--fix', action='store_true',
                          help='Apply repairs (default: dry-run report only)')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        'info': cmd_info,
        'ls': cmd_ls,
        'cat': cmd_cat,
        'extract': cmd_extract,
        'inject': cmd_inject,
        'mkdir': cmd_mkdir,
        'rm': cmd_rm,
        'check': cmd_check,
        'mkfs': cmd_mkfs,
        'repair': cmd_repair,
    }

    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main() or 0)
