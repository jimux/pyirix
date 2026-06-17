#!/usr/bin/env python3
"""gl_modules — partition a DWARF-bearing IRIX ELF's functions into their source
modules using the .debug_line table (address -> source file), joined with the
Ghidra-exported function list (libgl_map.json: [{a,n,callees,...}]).

Outputs libgl_modules.json:
  { "by_func":  {func_name: "dgl/comm.c", ...},
    "by_module": {"dgl/comm.c": [func_name, ...], ...},
    "module_ranges": [[start,end,"file"], ...] }

  python3 gl_modules.py [ELF] [MAP_JSON] [OUT_JSON]
defaults: /workspace/libgl.bin  /workspace/libgl_map.json  /workspace/libgl_modules.json
"""
import json, sys, subprocess, re, bisect, os, collections

ELF = sys.argv[1] if len(sys.argv) > 1 else "/workspace/libgl.bin"
MAP = sys.argv[2] if len(sys.argv) > 2 else "/workspace/libgl_map.json"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/workspace/libgl_modules.json"


def line_table(elf):
    """Return sorted [(addr, sourcefile)] breakpoints from .debug_line."""
    out = subprocess.run(["readelf", "--debug-dump=decodedline", elf],
                         capture_output=True, text=True).stdout
    pts = []
    cur_file = None
    for ln in out.splitlines():
        # CU group header like "branch.c:" sets context but data rows carry the file too
        m = re.match(r"^(\S+\.\w+)\s+(\d+|-)\s+(0x[0-9a-fA-F]+)", ln)
        if m:
            f, _, addr = m.group(1), m.group(2), m.group(3)
            pts.append((int(addr, 16), f))
    pts.sort()
    # collapse consecutive same-file points; keep file-change boundaries
    return pts


def cu_files(elf):
    """Map each CU to its full path name via aranges offset -> .debug_info DW_AT_name."""
    # use pyelftools just for the section bytes + aranges; DIE parse fails but the
    # CU DW_AT_name string sits at the CU offset, so grep it.
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return {}
    e = ELFFile(open(elf, "rb"))
    info = e.get_section_by_name(".debug_info").data()
    names = {}
    # find every "../<dir>/<file>.c" looking string and its offset (heuristic anchor)
    for m in re.finditer(rb"\.\./[\w./-]+\.c", info):
        names[m.start()] = m.group().decode()
    return names


def main():
    pts = line_table(ELF)
    if not pts:
        print("no .debug_line data; aborting"); return
    addrs = [a for a, _ in pts]
    files = [f for _, f in pts]

    def file_at(pc):
        i = bisect.bisect_right(addrs, pc) - 1
        return files[i] if i >= 0 else None

    fns = json.load(open(MAP))
    by_func = {}
    by_module = collections.defaultdict(list)
    unbucketed = 0
    for f in fns:
        mod = file_at(f["a"])
        if mod is None:
            unbucketed += 1
            mod = "?"
        by_func[f["n"]] = mod
        by_module[mod].append(f["n"])

    # module address ranges (contiguous runs of same file in the line table)
    ranges = []
    run_start, run_file = pts[0]
    for a, fl in pts[1:]:
        if fl != run_file:
            ranges.append([run_start, a, run_file]); run_start, run_file = a, fl
    ranges.append([run_start, addrs[-1], run_file])

    json.dump({"by_func": by_func,
               "by_module": {k: sorted(v) for k, v in by_module.items()},
               "module_ranges": ranges},
              open(OUT, "w"))
    print(f"functions: {len(fns)}  bucketed: {len(fns)-unbucketed}  unbucketed: {unbucketed}")
    print(f"distinct modules: {len(by_module)}  -> {OUT}")
    for mod in sorted(by_module, key=lambda m: -len(by_module[m]))[:25]:
        print("  %4d  %s" % (len(by_module[mod]), mod))


if __name__ == "__main__":
    main()
