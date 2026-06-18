# `pyirix.efs` — EFS Filesystem Tools

> Part of the [pyirix documentation](../README.md).

EFS (Extent File System) is the older SGI filesystem, used on install media and pre-6.x disks. `pyirix.efs` is **read-only**: it locates an EFS partition inside an SGI disk image and walks its inodes, extents, directories, and symlinks to list or extract files.

## How it works

An SGI disk image begins with a 512-byte **volume header** (magic `0x0BE5A941`) holding a 16-entry partition table. `find_efs_partition()` reads that header and returns the byte offset/size of the first partition typed EFS (`7`) or sysv (`5`). If there is no volume header, it falls back to probing for an EFS superblock magic (`0x072959`/`0x07295A`) at block 1 and treats the whole file as one partition.

The EFS superblock (at block 1 of the partition) describes the cylinder-group geometry. Inodes are 128 bytes, 4 per 512-byte basic block; `read_inode()` maps an inode number to its block with the `EFS_ITOBB` arithmetic (`fs_firstcg + cg*fs_cgfsize + (ino>>2)%fs_cgisize`) and parses the core fields plus up to 12 **direct extents**. Each extent packs a 24-bit block number, an 8-bit length, and a 24-bit file offset into 8 bytes. Files needing more than 12 extents use indirect extent blocks, which `get_all_extents()` follows. `read_file_data()` sorts extents by file offset, reads each run, and truncates to the inode size. Directories use a slot-table block format (magic `0xBEEF`): a slot array at the top of each 512-byte block points at packed `(inode, namelen, name)` entries.

## Key functions (`pyirix.efs.reader`)

```python
from pyirix.efs.reader import (
    find_efs_partition,    # (f) -> (part_offset, part_size) | None
    read_superblock,       # (f, part_offset) -> dict | None
    read_inode,            # (f, part_offset, sb, ino) -> dict | None
    read_dir_entries,      # (f, part_offset, sb, inode) -> [(name, ino), ...]
    read_file_data,        # (f, part_offset, sb, inode) -> bytes
    read_symlink_target,   # (f, part_offset, sb, inode) -> str
    list_recursive,        # walk + print a long listing
    count_files,           # (...) -> (files, dirs, symlinks, total_bytes)
    extract_recursive,     # (...) -> stats dict
    EFS_ROOT_INODE,        # 2
)
```

`read_inode` returns a dict with `mode, nlink, uid, gid, size, atime, mtime, ctime, gen, numextents, version, extents`. `read_dir_entries` returns `(name, inode_number)` tuples with `.`/`..` removed.

## Usage

```python
from pyirix.efs.reader import find_efs_partition, read_superblock, extract_recursive, EFS_ROOT_INODE

with open("Foundation1.img", "rb") as f:
    result = find_efs_partition(f)        # locate the EFS partition
    if not result:
        print("No EFS partition found")
    else:
        part_offset, part_size = result
        sb = read_superblock(f, part_offset)

        # Extract only the dist/ subtree. Signature:
        #   extract_recursive(f, part_offset, sb, inode_num, path, dest_dir,
        #                      path_filter=None, stats=None) -> stats dict
        stats = extract_recursive(
            f, part_offset, sb, EFS_ROOT_INODE,
            "/", "/tmp/extracted", path_filter="dist",
        )
        print(f"{stats['files']} files, {stats['symlinks']} symlinks, {stats['errors']} errors")
```

The `path_filter` selects a subtree: a path is in scope if it equals the filter, is inside it, or is an ancestor of it (so traversal descends toward the target). Extracted directories are remapped relative to the filter prefix; symlinks are recreated with `os.symlink`; device/FIFO nodes are skipped.

## CLI

```bash
python -m pyirix.efs.reader info    Foundation1.img              # VH + partitions + superblock + file counts
python -m pyirix.efs.reader list    Foundation1.img [--path dist]  # long listing, optional subtree
python -m pyirix.efs.reader extract Foundation1.img /tmp/out [--path dist]
```

## Bulk extraction (`pyirix.efs.extract`)

A driver over a fixed 16-entry manifest of known IRIX CD images, used to populate `software_library/extraced_irix_cds/`. It dispatches per entry to one of four extractors — raw EFS, EFS `install/`-remapped-to-`dist/`, `tar.gz`, or nested-tar (`--strip-components`) — and skips work that is already done (detected by a populated `dist/`).

```python
from pyirix.efs.extract import extract_cd_set   # convenience entry used by tooling
```

```bash
python -m pyirix.efs.extract --check            # report which manifest entries are extracted / missing
python -m pyirix.efs.extract                    # extract everything not yet done
python -m pyirix.efs.extract --only 3,7 --force # re-extract specific entries
```

Two related standalone scripts package a host directory **into** an EFS image: `create_kern_src.py` (walks the IRIX 6.5.5 kernel source tree into a raw EFS via `analysis_tools.tar2efs.EFSBuilder`) and `wrap_with_vh.py` (prepends an SGI volume header so IRIX's `dksc` driver recognizes it). Both are run from the project root and use hardcoded paths.

## Creating EFS images (`pyirix.efs.builder`)

`EFSImageBuilder` and the `mkfs_efs()` convenience build a complete EFS filesystem from scratch — geometry, cylinder groups, inodes, `0xBEEF` directory blocks, indirect extents, the superblock checksum, and (optionally) an SGI volume header. This is the canonical builder; `pyirix.dist.combine` re-exports it.

```python
from pyirix.efs import mkfs_efs

mkfs_efs("disk.img",
         files={"/etc/motd": b"hello\n", "/usr/share/big.dat": big_bytes},
         symlinks={"/etc/rc": "/etc/motd"},
         dirs=["/empty"])
# with_volume_header=True (default) wraps the EFS partition in an SGI volume
# header at sector 64; pass with_volume_header=False for a raw EFS partition.
```

The build is self-verifying and round-trips through `pyirix.efs.reader`.

## Diagnostics & repair (`pyirix.efs.repair`)

```python
from pyirix.efs import check_efs, verify_checksum, recover_superblock

with open("disk.img", "rb") as f:
    report = check_efs(f)          # partition, sb magic, checksum, geometry, root dir
    print(report.summary())        # e.g. "PASS=5"
```

`check_efs` returns a structured `CheckReport` (PASS/INFO/WARN/FAIL findings). `verify_checksum` recomputes the XOR-rotate superblock checksum. Every EFS has a replica superblock at block `fs_replsb` (and at `fs_size-1`); `recover_superblock(f, part_offset, dry_run=False)` rewrites a corrupt primary from the replica — locating it by `fs_replsb` or, if the primary is unreadable, by scanning for the EFS magic.
