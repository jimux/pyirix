# Building a bootable IRIX root from scratch with pyirix

This document describes how the pyirix filesystem tooling was used to build a minimal IRIX 6.5 root filesystem **entirely from scratch** — no real install, no `mkfs.xfs`, no disk imaging — that boots the emulated SGI IP54 all the way to an interactive single-user shell. It doubles as a worked example of the EFS/XFS creation API and a record of the IRIX boot requirements we reverse-engineered along the way.

## TL;DR

`pyirix.xfs.mkfs` writes a valid IRIX **V1-directory XFS** from scratch; `pyirix.xfs.operations` populates it with files, directories, symlinks, and device nodes. `pyirix_qemu/build_minimal_root.py` ties these together: it copies the kernel and a handful of binaries out of a reference disk, lays down a minimal `/etc/inittab` plus the `/dev` and `/hw` plumbing, and produces a disk image that

- passes IRIX's own `xfs_check` clean, and
- boots IRIX 6.5 on `sgi-ip54` to `INIT: SINGLE USER MODE` and a working `#` shell prompt.

```bash
python3 -m pyirix_qemu.build_minimal_root \
    --source vm_instances/ip54-test/disk.qcow2 \
    --out /tmp/minroot.img --size-mb 96
```

## Why this is non-trivial

Modern `mkfs.xfs` only creates XFS v5 (CRC, dir2 directories), which neither the IRIX PROM nor the IRIX kernel can read, and the Linux kernel in turn refuses to mount the original IRIX V1-directory format. So neither side's standard tools can produce or validate an IRIX root filesystem. pyirix fills that gap: it writes the version-4 / DIRV2-clear superblock, V1 short-form and leaf directories (`0xFEEB`), V1 inodes (link count in `di_onlink`), and the AGF/AGI/B+tree metadata that the IRIX PROM and kernel expect. The only authoritative validator for the result is IRIX itself, which is why the final proof is a real boot under QEMU.

## The tooling used

| Capability | API |
|------------|-----|
| Create a V1 XFS from scratch | `pyirix.xfs.mkfs.mkfs_xfs` / `make_xfs_image` |
| Create directories | `pyirix.xfs.operations.mkdir` |
| Write regular files (e.g. the kernel) | `pyirix.xfs.operations.create_file` |
| Create symlinks | `pyirix.xfs.operations.create_symlink` |
| Create device nodes | `pyirix.xfs.operations.mknod` |
| Read files/symlinks/dev words from a source disk | `read_file_data`, `read_symlink`, `read_dev` |
| Validate / repair | `pyirix.xfs.repair.check_xfs`, `repair_xfs` |

`create_symlink` and `mknod` were added specifically for this work — a bootable root needs `/dev/console` (a character device) and `/etc/init` / `/dev/root` (symlinks), none of which a plain file-writer can produce.

## The minimal file set (and why each piece is required)

Every entry below was made mandatory by an observed IRIX boot failure; the "symptom if missing" column is the actual kernel message that led us to add it.

| Path | Kind | Why it's needed | Symptom if missing |
|------|------|-----------------|--------------------|
| `/unix.new` | file | The IP54-patched kernel the bootloader actually loads (NVRAM bootfile is `/unix.new`, not `/unix`) | `Unable to load bootfile` |
| `/etc/init` | symlink → `../sbin/init` | The kernel icode exec's the literal path `/etc/init` (`kern/ml/csu.s`) | `PANIC: init died (what=0x2)` (ENOENT) |
| `/sbin/init` | file | PID 1 (dynamically linked, n32) | — |
| `/sbin/sh` | file | The single-user shell (statically linked) | shell can't start |
| `/lib32/rld` | file | Runtime linker for the dynamic `/sbin/init` | init can't load |
| `/lib32/libc.so.1` | file | init's `PT_INTERP` / libc | init can't load |
| `/hw` | dir | Mount point for `hwgfs` (the hardware graph); device paths resolve through it | `Unable to mount hwgfs error = 2` |
| `/dev/console` | char dev | The console the kernel and init open | init has no console |
| `/dev/{null,tty,systty,zero}` | char dev | Standard devices | various |
| `/dev/root`, `/dev/swap` | symlinks → `/hw/disk/...` | Root and swap device links | swap/root resolution warnings |
| `/etc/inittab` | file | Tells init what to run; see below | init has no run table |
| `/etc`, `/var`, `/tmp`, `/proc`, `/lib32`, `/sbin`, `/dev` | dirs | Standard mount points / parents | — |

The device nodes are created with `mknod` using the exact raw dev words read from a real IRIX disk (e.g. `/dev/console` = `0x00e80000`, `/dev/null` = `0x00040002`).

### The minimal inittab

```
is:S:initdefault:
su:S:wait:/sbin/sh </dev/console >/dev/console 2>&1
```

`initdefault: S` boots straight to single user; the `su` line runs the static `/sbin/sh` on the console, skipping the entire `rc` sequence.

## How to build it

The assembler reads the kernel and binaries out of a reference disk (so we don't ship copyrighted IRIX binaries), then writes a fresh image:

```bash
# VH-wrapped image (bootable on the PROM); use --raw for a bare partition that
# IRIX's `xfs_check -f` reads directly.
python3 -m pyirix_qemu.build_minimal_root \
    --source vm_instances/ip54-test/disk.qcow2 \
    --out /tmp/minroot.img --size-mb 96
```

Library-level, the same thing in a few lines:

```python
from pyirix.xfs.mkfs import mkfs_xfs
from pyirix.xfs.image import open_disk_image, find_xfs_partition
from pyirix.xfs.superblock import read_superblock
from pyirix.xfs.operations import mkdir, create_file, create_symlink, mknod
from pyirix.xfs.constants import S_IFCHR

mkfs_xfs("/tmp/root.img", size_mb=96, agcount=1)
with open_disk_image("/tmp/root.img", writable=True) as f:
    po, _ = find_xfs_partition(f); sb = read_superblock(f, po)
    for d in ("/sbin", "/etc", "/dev", "/lib32", "/hw", "/var", "/tmp", "/proc"):
        mkdir(f, po, sb, d)
    create_file(f, po, sb, "/unix.new", kernel_bytes, mode=0o755)
    create_file(f, po, sb, "/sbin/init", init_bytes, mode=0o755)
    create_symlink(f, po, sb, "/etc/init", "../sbin/init")
    mknod(f, po, sb, "/dev/console", S_IFCHR | 0o622, 0x00E80000)
    create_file(f, po, sb, "/etc/inittab",
                b"is:S:initdefault:\nsu:S:wait:/sbin/sh </dev/console >/dev/console 2>&1\n",
                mode=0o644)
    # ... + the rest of the file set above
```

## How to boot and validate it

The IP54 machine attaches exactly one disk (`drive_get(IF_MTD, 0, 0)`), so booting a custom root means presenting it as that disk. **Never overwrite the shared instance disk** — set up a throwaway instance instead:

```bash
# 1. Convert the raw image to qcow2 (the instance disk format).
qemu-img convert -f raw -O qcow2 /tmp/minroot.img /tmp/minroot.qcow2

# 2. Make a throwaway instance: a new dir with our disk + a copy of the
#    reference NVRAM/manifest (NVRAM carries the console + boot settings).
mkdir -p vm_instances/minroot-boot
cp /tmp/minroot.qcow2            vm_instances/minroot-boot/disk.qcow2
cp vm_instances/ip54-test/nvram.bin.golden vm_instances/minroot-boot/nvram.bin
cp vm_instances/ip54-test/manifest.json     vm_instances/minroot-boot/manifest.json   # then edit "name"

# 3. Boot it (MCP): qemu_session_start instance=minroot-boot autoload=true
# 4. Clean up: vm_instance_delete minroot-boot
```

To validate the filesystem without booting, run IRIX's own checker on a `--raw` image copied into a running guest: `xfs_check -f /tmp/minroot.xfs` returns 0 (clean). To capture the full boot log past the kernel's panic-reboot loop, run QEMU directly with `-serial file:/tmp/boot.log` (the binary is `qemu/build-linux/qemu-system-mips64`; copy the exact arguments from `ps` of a running session).

## What a successful boot looks like

```
NOTICE: pvdisk: IP54 paravirtual disk, 196672 sectors (96 MB), root partition 0 at LBA 64
Root on device /hw/scsi_ctlr/0/target/1/lun/0/disk/partition/0/block (fstype xfs)
INIT: SINGLE USER MODE
#
```

The shell is fully interactive — it runs commands and reads the from-scratch filesystem:

```
# echo BOOTED_FROM_SCRATCH=$?
BOOTED_FROM_SCRATCH=0
# while read l; do echo "INITTAB: $l"; done < /etc/inittab
INITTAB: is:S:initdefault:
INITTAB: su:S:wait:/sbin/sh </dev/console >/dev/console 2>&1
```

## The debugging journey

Each boot attempt surfaced one missing piece; the IRIX kernel's error messages were precise enough to fix it directly. This sequence is worth keeping because it documents exactly what IRIX requires:

1. **`Unable to load bootfile`** — the NVRAM bootfile is `/unix.new` (the IP54-patched kernel), not `/unix`. Copied `/unix.new`.
2. **`PANIC: init died (why=1, what=0x2)`** — `what=0x2` is ENOENT. The kernel icode exec's the literal `/etc/init` (`kern/ml/csu.s:626`), which on real disks is a symlink to `../sbin/init`. Added the symlink (this is why `create_symlink` had to exist).
3. **`Unable to mount hwgfs error = 2`** — `hwgfs` (the hardware graph) mounts at `/hw`, which must exist as a directory. Added `/hw`.
4. Non-fatal noise that single user tolerates: `Failed to add swap file /dev/swap error 2` (we ship no swap partition), and `Cannot open /etc/TIMEZONE` / `/etc/ioctl.syscon` / `/var/adm/utmp` / `/etc/passwd damaged` / `Can't start /bin/csh` (all optional userland files init warns about and continues past).

Before any of this, IRIX's `xfs_check` also caught three filesystem-level bugs that pure round-trip tests (pyirix reading its own output) could not — free inodes needing valid magic, V1 inode link counts living in `di_onlink`, and v2 inodes requiring the superblock `NLINKBIT`. Those fixes are locked in by `tests/test_xfs_mkfs.py::TestXFSIrixCompat`.

## Caveats and scope

- The root is mounted, written, and booted single-user; we do not bring up multi-user (that needs the full `/etc/rc2.d` sequence and far more userland).
- The internal log is zeroed-clean (no real log record); IRIX accepts it on a clean first mount.
- No swap partition is created, so init prints a (harmless) swap warning.
- The assembler copies IRIX binaries from a reference disk you supply; it does not contain any IRIX code itself.

## See also

- `pyirix/README.md` — the `pyirix.xfs` create / repair / mkfs reference.
- `pyirix_qemu/build_minimal_root.py` — the assembler (its comments cite the kernel sources for each requirement).
- `tests/test_xfs_mkfs.py` — `TestXFSSpecialFiles` (symlink/mknod) and `TestXFSIrixCompat` (the xfs_check-found fixes).
