#!/usr/bin/env python3
"""kernel_syms — generate a correct kernel symbol JSON from the ACTUAL kernel,
and detect symbol drift against a (possibly stale) JSON.

The ip54_kernel_symbols_*.json files drift badly when the kernel is rebuilt —
every address shifts, so gdb breakpoints silently hit WRONG addresses (see
memory kernel_symbol_drift).  ALWAYS regenerate from the running kernel.

Run inside the docker dev container (needs readelf; uses the MCP fs_extract for
disk images).

Usage:
  # from a kernel ELF on disk:
  python3 kernel_syms.py gen --elf /workspace/_golden_extract/unix --out syms.json

  # from a disk image (extracts /unix first):
  python3 kernel_syms.py gen --image vm_instances/ip54-test/disk.qcow2.golden \
      --kpath /unix --out ip54_kernel_symbols_golden.json

  # drift check: compare a JSON against the real kernel ELF
  python3 kernel_syms.py drift --elf /workspace/_golden_extract/unix \
      --json /workspace/ip54_kernel_symbols_disk.json
"""
import argparse, json, os, re, subprocess, sys, tempfile

PROBE = ["splx", "idevGenPtrEvent", "idev_rput", "qcntlpoll", "schedule",
         "vfault", "cmn_err", "shmiq_sproc"]


def elf_syms(elf):
    r = subprocess.run(["readelf", "-sW", elf], capture_output=True, text=True)
    out = {}
    syms = []
    for ln in r.stdout.splitlines():
        m = re.match(r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+\w+\s+\S+\s+(\S+)", ln)
        if not m:
            continue
        addr, size, typ, bind, name = m.groups()
        if typ in ("FUNC", "OBJECT") and name:
            a = int(addr, 16)
            syms.append({"name": name, "address": a, "size": int(size),
                         "type": typ, "bind": bind})
            out.setdefault(name, a)
    return syms, out


def extract_unix(image, kpath):
    """Extract a single file (e.g. /unix) from an XFS disk image to a temp
    dir and return its host path. Pure pyirix — handles raw and qcow2."""
    from pyirix.xfs.image import open_disk_image, find_xfs_partition
    from pyirix.xfs.superblock import read_superblock
    from pyirix.xfs.inode import read_inode, read_file_data
    from pyirix.xfs.operations import resolve_path

    dest = tempfile.mkdtemp(prefix="kunix_")
    with open_disk_image(image) as f:
        part = find_xfs_partition(f)
        if not part:
            raise RuntimeError(f"no XFS partition in {image}")
        off, _ = part
        sb = read_superblock(f, off)
        ino = resolve_path(f, off, sb, kpath)
        if ino is None:
            raise RuntimeError(f"{kpath} not found in {image}")
        inode = read_inode(f, off, sb, ino)
        data = read_file_data(f, off, sb, inode)
    out = os.path.join(dest, os.path.basename(kpath))
    with open(out, "wb") as fh:
        fh.write(data)
    return out


def cmd_gen(a):
    elf = a.elf or extract_unix(a.image, a.kpath)
    syms, _ = elf_syms(elf)
    json.dump(syms, open(a.out, "w"))
    print(f"wrote {len(syms)} symbols from {elf} -> {a.out}")


def cmd_drift(a):
    _, real = elf_syms(a.elf)
    stale = {s["name"]: (s["address"] & 0xffffffffffffffff)
             for s in json.load(open(a.json))}
    common = [n for n in real if n in stale]
    drift = [n for n in common if real[n] != stale[n]]
    print(f"=== drift check: {a.json} vs {a.elf} ===")
    print(f"common symbols: {len(common)}, drifted: {len(drift)} "
          f"({100*len(drift)//max(1,len(common))}%)")
    for n in PROBE:
        if n in real and n in stale:
            mark = "DRIFT" if real[n] != stale[n] else "ok"
            print(f"  {n:18} json=0x{stale[n]&0xffffffff:08x} "
                  f"real=0x{real[n]&0xffffffff:08x}  [{mark}]")
    if len(drift) > len(common) // 10:
        print("!!! JSON IS STALE — regenerate with: kernel_syms.py gen --elf "
              f"{a.elf} --out <json>")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("--elf"); g.add_argument("--image")
    g.add_argument("--kpath", default="/unix"); g.add_argument("--out", required=True)
    g.set_defaults(fn=cmd_gen)
    d = sub.add_parser("drift")
    d.add_argument("--elf", required=True); d.add_argument("--json", required=True)
    d.set_defaults(fn=cmd_drift)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
