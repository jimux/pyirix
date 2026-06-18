# pyirix

Python library for working with SGI/IRIX software. It reads the two SGI on-disk filesystems (**EFS** and **XFS**), parses and reasons about IRIX distribution media (**`.idb`/spec/`.sw`** packaging), and provides a toolkit for **statically analyzing and live-debugging** IRIX MIPS binaries. The filesystem and packaging tools are pure standard-library Python and need no QEMU; only the live kernel debugger talks to a running guest.

For QEMU orchestration (session management, disk creation, automated installation, the disc-image catalog), see the companion `pyirix_qemu` package.

---

## At a glance

| Subpackage | What it covers | QEMU? | In-depth docs |
|------------|----------------|-------|---------------|
| `pyirix.efs` | Read/extract **and create (mkfs)** SGI EFS images; diagnose/repair | No | [docs/efs.md](docs/efs.md) |
| `pyirix.xfs` | Full **read + write + create (mkfs)** of SGI XFS (incl. IRIX V1 dirs); diagnose/repair; raw and qcow2 | No (qcow2 needs `qemu-img`) | [docs/xfs.md](docs/xfs.md) |
| `pyirix.dist` | Parse `.idb`/spec/`.sw` packaging; dependency/conflict analysis; build composite install images | No | [docs/dist.md](docs/dist.md) |
| `pyirix.debug` | Static ELF analysis (disasm, symbols, xrefs, DWARF) + a live `gdb-multiarch` driver | Only `guest_gdb` | [docs/debug.md](docs/debug.md) |
| `pyirix.prom` | SGI PROM support: KSEG address math, platform definitions, PROM file loader (used by `pyirix.debug` disassembly) | No | — |

Every subpackage exposes both a **library API** and a **CLI** (`python3 -m pyirix.<pkg>...`).

---

## Dependencies

- Python 3.8+
- Standard library only for `pyirix.efs`, `pyirix.xfs`, and `pyirix.dist`
- `pyirix.xfs` shells out to `qemu-img` only when operating on **qcow2** images (raw images need nothing)
- Optional: `capstone` for the MIPS disassembly helpers in `pyirix.debug` (`mips_disasm`, `disasm`); the PROM support they need lives in the self-contained `pyirix.prom` subpackage
- `pyirix.debug.guest_gdb` additionally needs `gdb-multiarch` and a QEMU process exposing a gdbstub (`-gdb`)

---

## Installation

```bash
# Editable install from source
pip install -e /path/to/qemu-sgi/pyirix

# Or just add the project root to PYTHONPATH
export PYTHONPATH=/path/to/qemu-sgi:$PYTHONPATH
```

---

## Documentation

In-depth guides live in [`docs/`](docs/). Each subpackage's full API, usage, CLI, and gotchas are broken out there; this README stays an overview.

| Document | What's inside |
|----------|---------------|
| [docs/efs.md](docs/efs.md) | EFS: read/extract, the `mkfs_efs` builder, and diagnostics/repair (checksum, replica recovery) |
| [docs/xfs.md](docs/xfs.md) | XFS: the layered architecture, read/write/create (`mkfs_xfs`), special files (symlink/mknod), CLI, repair, and gotchas |
| [docs/dist.md](docs/dist.md) | IRIX packaging: the spec/`.idb`/`.sw` model, dependency/conflict analysis, install simulation, family resolution, and image building |
| [docs/debug.md](docs/debug.md) | Binary analysis: the static ELF tools (disasm, symbols, xrefs, DWARF) and the live `gdb-multiarch` kernel driver |
| [docs/building-a-bootable-irix-root.md](docs/building-a-bootable-irix-root.md) | Worked example: assembling a from-scratch IRIX root that boots to a single-user shell, the minimal file set, and how to build/boot/validate it |

---

## Module Summary

| Module | Purpose |
|--------|---------|
| `pyirix.efs.reader` | EFS volume-header/superblock/inode parser; recursive list, count, extract |
| `pyirix.efs.builder` | Create EFS images from scratch (`mkfs_efs`, `EFSImageBuilder`, volume header) |
| `pyirix.efs.repair` | EFS diagnostics (`check_efs`), checksum verify, replica-superblock recovery |
| `pyirix.efs.extract` | Manifest-driven bulk extractor for known IRIX CD images |
| `pyirix.xfs.image` | Disk image layer: SGI volume header, partitions, transparent raw/qcow2 |
| `pyirix.xfs.superblock` | XFS superblock read/write, SASH-compat check, log zeroing |
| `pyirix.xfs.inode` | Inode read/write, data fork (local/extents/btree), file data, symlinks |
| `pyirix.xfs.directory` | V1 shortform/leaf and dir2 shortform/block directory read & mutate |
| `pyirix.xfs.ondisk` | Parse/pack of every on-disk structure + address-conversion helpers |
| `pyirix.xfs.btree` | Generic B+tree cursor (alloc/inobt/bmap), `CntBTreeCursor` |
| `pyirix.xfs.alloc` / `ialloc` | Block and inode allocation/free via AGF/AGI B+trees |
| `pyirix.xfs.operations` | High-level path ops: resolve, list, extract, create, write, delete, symlink, mknod, mkdir/rmdir, chmod/chown |
| `pyirix.xfs.mkfs` | Create an IRIX V1-directory XFS from scratch (`mkfs_xfs`, `make_xfs_image`) |
| `pyirix.xfs.repair` | XFS diagnostics (`check_xfs`/`repair_xfs`), version-bit fix, secondary-superblock recovery, log zeroing |
| `pyirix.xfs.constants` | Magic numbers, format codes, `XFSError` hierarchy |
| `pyirix.dist.analyzer` | Extracted-CD scan: subsystem catalog, text-scan deps, conflicts |
| `pyirix.dist.parser` | Binary spec parser + `Corpus` index + conflict report (version ranges) |
| `pyirix.dist.pkg_analyzer` | `DepExprParser`, `InstSimulator`, SQLite `PackageDatabase`, `FamilyResolver` |
| `pyirix.dist.pkg_selector` | Curses TUI for family selection and CD-set resolution |
| `pyirix.dist.combine` | Build a combined bootable EFS install image from dist dirs |
| `pyirix.dist.idb` | Structured `.idb` manifest parser (`IDB`/`IDBEntry`) |
| `pyirix.dist.archive` | Extract files from `.sw` archives (LZW/`compress` aware) |
| `pyirix.dist.audit` | Cross-check installed files on a disk against `.idb` manifests |
| `pyirix.dist.patch` | Fix the malformed `motif_eoe.sw64.uil` spec record |
| `pyirix.debug.dwarf` | From-scratch SGI MIPS_DWARF2 parser (structs/funcs/vars) |
| `pyirix.debug.disasm` | Disassemble a kernel function by name |
| `pyirix.debug.mips_disasm` | Capstone MIPS64/BE wrapper with hardware annotations |
| `pyirix.debug.mipsasm` | Assemble MIPS asm → big-endian words (PROM trampolines) |
| `pyirix.debug.strings` | Resolve `lui+addiu`/`ori` string references |
| `pyirix.debug.syscalls` | Inventory ioctl/syscall command constants |
| `pyirix.debug.xref` | Find callers via a `jal <target>` scan |
| `pyirix.debug.callgraph` | Whole-binary direct-call graph + path queries |
| `pyirix.debug.dataref` | Find data-word references to an address |
| `pyirix.debug.syms` | Generate / drift-check canonical kernel-symbol JSON |
| `pyirix.debug.modules` | Partition DWARF-bearing ELFs into source modules |
| `pyirix.debug.guest_gdb` | Drive `gdb-multiarch` against the live QEMU MIPS64 kernel |
| `pyirix.prom.config` | KSEG address math, PROM header offsets, SGI platform table, platform detection |
| `pyirix.prom.hardware_defs` | MMIO register/device definitions; address annotation for disassembly |
| `pyirix.prom.prom_loader` | Load/normalize PROM image files; extract metadata (platform, endian, vectors) |
