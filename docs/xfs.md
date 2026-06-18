# `pyirix.xfs` — XFS Filesystem (Read + Write + Create)

> Part of the [pyirix documentation](../README.md).

XFS is the IRIX 6.x system-disk filesystem. `pyirix.xfs` reads **and writes** it, covering both the IRIX **V1** format (directory magic `0xFEEB`) and the **V4/dir2** format (block magic `XD2B`). It is the engine behind the project's `xfs_*` MCP tools — injecting kernels, editing config files, repairing superblocks.

> ⚠️ Writing into a live IRIX system disk is delicate. Project experience: apply config changes **live** (inside the running guest) rather than via offline injection, which has corrupted XFS images and triggered fsck panics. Treat the write API as a power tool.

## Architecture

The library is layered, bottom to top:

| Layer | Module | Role |
|-------|--------|------|
| Image | `image.py` | Find the SGI volume header + XFS partition; transparent raw/qcow2 access |
| Structures | `ondisk.py` | `parse_*`/`pack_*` for every on-disk struct + address conversions |
| Superblock | `superblock.py` | Read/write/validate; SASH-compat; log zeroing |
| Inode | `inode.py` | Inode core + data fork (local/extents/btree), file data, symlinks |
| Directory | `directory.py` | All four directory formats (V1 sf/leaf, dir2 sf/block) |
| B+tree | `btree.py` | Generic cursor over alloc/inobt/bmap trees |
| Allocation | `alloc.py`, `ialloc.py` | Block and inode allocation/free via AGF/AGI B+trees |
| Operations | `operations.py` | Path resolve, list, extract, create, write, delete, mkdir/rmdir, chmod/chown |
| CLI | `__main__.py` | `python3 -m pyirix.xfs` |

All on-disk structures are big-endian. `ondisk.py` guarantees `pack(parse(raw)) == raw` for every structure, so reads survive a round-trip back to disk untouched.

## How it works

`open_disk_image(path, writable=False)` is a context manager. For **raw** images it just opens the file. For **qcow2** it converts to a temp raw file via `qemu-img convert -O raw` on entry, and — if `writable` — converts back to qcow2 on exit, replacing the original (a full re-conversion, so don't interrupt it). `find_xfs_partition()` reads the volume header and returns the partition typed `10` (XFS); `read_superblock()` validates magic `XFSB`.

Reads flow through the on-disk address helpers: `ino_to_offset()` decomposes an inode number into AG number / AG block / inode slot; `fsblock_to_offset()` decomposes a filesystem block into AG + block. Inodes carry a **data fork** in one of three formats — `LOCAL` (inline data), `EXTENTS` (packed 16-byte bmbt records), or `BTREE` (a bmap B+tree the `BTreeCursor` walks). Directories dispatch on format too: shortform directories live inline in the inode; larger ones become on-disk leaf/block directories keyed by the `xfs_da_hashname()` hash.

Writes are the interesting part. `write_file_data()` **always** writes regular files as `EXTENTS`, never `LOCAL` — IRIX 6.5 XFS flags inline regular files as corrupt — allocating at least one block even for empty files. Allocation walks the AGF's two free-space B+trees (by-block and by-count), splitting/merging extents and keeping `agf_freeblks`/`agf_longest` consistent; inode allocation walks the AGI's inobt, flipping free bits or carving a fresh 64-inode chunk. After any structural change, operations call `write_superblock()` and `zero_log()` so IRIX won't replay a stale journal on mount.

## Library API

```python
from pyirix.xfs.image import open_disk_image, find_xfs_partition
from pyirix.xfs.superblock import read_superblock, sash_compatible
from pyirix.xfs.operations import resolve_path, list_dir, extract_recursive, create_file

with open_disk_image("disk.qcow2") as f:
    part_offset, part_size = find_xfs_partition(f)
    sb = read_superblock(f, part_offset)

    ok, reason = sash_compatible(sb)         # will the PROM/SASH boot this fs?
    print("SASH:", ok, reason)

    # List the root dir. Each entry: {name, ino, type, mode, uid, gid, size[, link_target]}
    for e in list_dir(f, part_offset, sb, "/"):
        print(e["type"], oct(e["mode"]), e["size"], e["name"])

    # Resolve a path to an inode, then extract that subtree to the host
    etc_ino = resolve_path(f, part_offset, sb, "/etc")
    extract_recursive(f, part_offset, sb, etc_ino, "/etc", "/tmp/etc_out")
```

Writing needs `writable=True` (and on qcow2 pays the reconvert-on-close cost):

```python
with open_disk_image("disk.qcow2", writable=True) as f:
    part_offset, _ = find_xfs_partition(f)
    sb = read_superblock(f, part_offset)
    create_file(f, part_offset, sb, "/etc/hello", b"hi\n", mode=0o644)
```

Key operations (`pyirix.xfs.operations`) — all take `(f, part_offset, sb, ...)`:

| Function | Purpose |
|----------|---------|
| `resolve_path(path)` | Path → inode number (no symlink following) |
| `resolve_path_follow_links(path)` | Path → inode, following symlinks (needed for `/bin/sh` → `usr/bin/sh`) |
| `list_dir(path='/')` | One directory, list of entry dicts |
| `list_recursive(ino, path, results, ...)` | Recursive walk into a results list |
| `extract_recursive(ino, path, dest)` | Extract subtree to host; returns `{files,dirs,symlinks,errors}` |
| `create_file(path, data, mode=0o100644)` | New file (raises `XFSExistsError` if present) |
| `write_file(path, data)` | Overwrite existing file (does not free old blocks) |
| `delete_file(path)` | Remove file/symlink (frees inode, not data blocks) |
| `create_symlink(path, target)` | New symbolic link (inline target) |
| `mknod(path, mode, rdev)` | New char/block device node (`mode` includes `S_IFCHR`/`S_IFBLK`; `rdev` = raw dev word) |
| `read_dev(path)` | Read a device node's raw dev word |
| `mkdir(path, mode=0o40755)` / `rmdir(path)` | Create / remove empty directory |
| `chmod(path, mode)` / `chown(path, uid, gid)` | Metadata only (no log zero) |

With `create_file`, `create_symlink`, `mknod`, and `mkdir`, the writer can lay down a complete root filesystem. `pyirix_qemu/build_minimal_root.py` does exactly that: it assembles a from-scratch single-user IRIX root (kernel `/unix.new`, the `/etc/init`→`../sbin/init` symlink, static `/sbin/sh`, dynamic `/sbin/init` + `/lib32/{rld,libc.so.1}`, a minimal `/etc/inittab`, `/hw` mount point, and `/dev` device nodes + symlinks) by copying binaries out of a real disk.

**This actually boots.** The result passes IRIX's own `xfs_check`, and a disk built this way boots IRIX 6.5 on the emulated IP54 all the way to an interactive single-user shell (`INIT: SINGLE USER MODE`, a `#` prompt that runs commands and reads the filesystem) — created entirely from scratch with pyirix tooling, no real install required. The required file set was reverse-engineered from IRIX's own boot panics (e.g. the kernel icode exec's `/etc/init`; hwgfs needs a `/hw` mount point). The full story, the minimal file set, and how to build/boot/validate it are in [`docs/building-a-bootable-irix-root.md`](docs/building-a-bootable-irix-root.md).

Errors raise an `XFSError` subclass: `XFSCorruptionError`, `XFSNoSpaceError`, `XFSPathError`, `XFSExistsError`, `XFSNotEmptyError`.

## CLI

```bash
python3 -m pyirix.xfs info    disk.qcow2                       # geometry, version, SASH compatibility
python3 -m pyirix.xfs ls      disk.qcow2 /etc [-r] [-n 5000]   # list (optionally recursive)
python3 -m pyirix.xfs cat     disk.qcow2 /etc/sys_id [-b]      # print a file (-b = raw binary)
python3 -m pyirix.xfs extract disk.qcow2 /unix -d /tmp/unix    # extract a subtree to the host
python3 -m pyirix.xfs inject  disk.qcow2 ./unix.new /unix.new  # host file -> guest (create or overwrite)
python3 -m pyirix.xfs mkdir   disk.qcow2 /tmp/newdir --mode 755
python3 -m pyirix.xfs rm      disk.qcow2 /tmp/oldfile          # file or empty dir
python3 -m pyirix.xfs check   disk.qcow2                       # read-only integrity probe
```

`check` reports PASS/FAIL/WARN/INFO for: partition found, superblock magic, SASH compatibility, root inode is a directory, root entry count, and path probes for `/unix`, `/unix.new`, `/stand`, `/sash`.

## Creating XFS images (`pyirix.xfs.mkfs`)

Modern `mkfs.xfs` only makes XFS v5 (CRC) with dir2 directories, which neither the IRIX PROM nor kernel can read. `pyirix.xfs.mkfs` builds the **original IRIX format** from scratch: a version-4 superblock with the DIRV2 bit clear, so directories use the V1 short-form / V1-leaf (`0xFEEB`) format and inodes are V1 (link count in `di_onlink`). It lays out the superblock (+ per-AG secondary copies), AGF/AGI/AGFL, the bnobt/cntbt/inobt B+tree leaves, a fully-initialized inode chunk (every slot carries a valid inode header), the root inode as an empty V1 short-form directory, and a zeroed internal log.

```python
from pyirix.xfs import mkfs_xfs, make_xfs_image

mkfs_xfs("disk.img", size_mb=16, agcount=1)     # default versionnum 0x0004 (V1 dirs/inodes)
img_bytes = make_xfs_image(size_mb=32, agcount=2, with_volume_header=True)
```

```bash
python3 -m pyirix.xfs mkfs disk.img --size-mb 16 --agcount 1 [--label NAME] [--raw]
```

The default `versionnum` is `0x0004` (minimal v4) because that is what IRIX's own `xfs_check` accepts cleanly. Real IRIX disks use `0x1094` (adds ATTR/ALIGN/EXTFLG), selectable via `make_xfs_image(versionnum=0x1094)`, but the ALIGN bit requires inode-chunk alignment this builder doesn't implement, so `xfs_check` warns about it.

**Validated against real IRIX.** A pyirix-created V1 XFS (populated with `mkdir`/`create_file`) was pushed into a running IRIX 6.5 guest and checked with IRIX's own tools: `xfs_check -f` reports it **clean**, and `xfs_db` reads the superblock, AG headers, root inode, and V1 short-form directory entries correctly. (The Linux XFS driver cannot do this — see the warning below.) The round-trip also exercises pyirix's own read and write paths, which uncovered and fixed several V1-inode correctness bugs now locked in by `tests/test_xfs_mkfs.py::TestXFSIrixCompat`.

> ⚠️ **The Linux kernel XFS driver cannot read/validate the original IRIX (V1) XFS format — do not use it as a test oracle.** Modern Linux removed V1-directory (dir1) support and deprecated v4; `mount -t xfs` rejects an IRIX V1 image at superblock validation (*"Superblock has unknown features enabled or corrupted feature masks", error -22*), even for a minimal `0x0004` superblock and even with the DIRV2 bit set. This is Linux's v4 validator, not a defect in the image. The authoritative oracle for IRIX V1 XFS is **IRIX itself** (mount it in the QEMU guest). EFS is different — the Linux `efs` driver *does* validate our images and matches pyirix byte-for-byte on real media.

## Diagnostics & repair (`pyirix.xfs.repair`)

```python
from pyirix.xfs import check_xfs, repair_xfs, recover_superblock, repair_version_bits

with open_disk_image("disk.img", writable=True) as f:
    part = find_xfs_partition(f); po = part[0] if part else 0
    report = check_xfs(f, po)            # CheckReport: sb magic/version, geometry,
    print(report.summary(), report.ok)   #   AG headers, root inode, log range
    if not report.ok and report.repairable:
        report, actions = repair_xfs(f, po, dry_run=False)
```

```bash
python3 -m pyirix.xfs repair disk.img          # dry-run report (exit 1 if FAILs)
python3 -m pyirix.xfs repair disk.img --fix    # apply repairs, re-check
```

Repairs available: `repair_version_bits` masks SASH-incompatible feature bits in a v4 superblock; `recover_superblock` rewrites a destroyed primary from a secondary copy (found via `find_secondary_superblock`, which scans AG starts for the `XFSB` magic); `clean_log` zeroes a dirty internal log. All default to `dry_run=True`.

## Gotchas worth knowing

- **No data-block freeing.** `delete_file` and `write_file` free/replace the inode and entries but leave old data blocks allocated (a deliberate simplification — wasted space, not corruption).
- **`chmod`/`chown` don't zero the log.** They are metadata-only and leave the journal dirty; IRIX replays it on next mount.
- **B+tree splits are single-level.** A leaf split that overflows its parent raises `XFSNoSpaceError` ("recursive split not yet implemented"). Fine for IRIX disk images, which rarely hit it.
- **qcow2 write-back is full re-conversion** on context-manager exit. Slow for large images; never kill the process mid-write.
