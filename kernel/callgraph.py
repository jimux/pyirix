#!/usr/bin/env python3
"""kcallgraph — whole-binary direct-call graph from `jal` edges in a MIPS ELF.
Builds caller->callee (and reverse) for every FUNC symbol and caches to JSON.
Indirect (jalr / function-pointer-table) calls are NOT captured here — use
kdataref.py to find where a function's pointer is stored (dispatch tables).

  KELF=/workspace/xsgi.bin KSYMS=/workspace/xsgi_symbols.json python3 kcallgraph.py build
  ... python3 kcallgraph.py callees <fn>
  ... python3 kcallgraph.py callers <fn>
  ... python3 kcallgraph.py path <from> <to>     # shortest call path (BFS)
"""
import json, struct, sys, bisect, os, collections

ELF = os.environ.get("KELF", "/workspace/_golden_extract/unix")
SYMS = os.environ.get("KSYMS", "/workspace/ip54_kernel_symbols_golden.json")
CG = os.environ.get("KCG", "/workspace/xsgi_callgraph.json")


def load(elf):
    d = open(elf, "rb").read()
    is64 = d[4] == 2
    shoff = struct.unpack(">Q" if is64 else ">I", d[(0x28 if is64 else 0x20):(0x30 if is64 else 0x24)])[0]
    es = struct.unpack(">H", d[(0x3a if is64 else 0x2e):(0x3c if is64 else 0x30)])[0]
    n = struct.unpack(">H", d[(0x3c if is64 else 0x30):(0x3e if is64 else 0x32)])[0]
    secs = []
    for i in range(n):
        e = d[shoff + i * es: shoff + (i + 1) * es]
        if is64:
            fl = struct.unpack(">Q", e[8:16])[0]; addr = struct.unpack(">Q", e[16:24])[0]
            off = struct.unpack(">Q", e[24:32])[0]; sz = struct.unpack(">Q", e[32:40])[0]
        else:
            fl = struct.unpack(">I", e[8:12])[0]; addr = struct.unpack(">I", e[12:16])[0]
            off = struct.unpack(">I", e[16:20])[0]; sz = struct.unpack(">I", e[20:24])[0]
        secs.append((fl, addr & 0xffffffff, off, sz))
    return d, secs


def build():
    d, secs = load(ELF)
    syms = json.load(open(SYMS))
    funcs = sorted((s["address"] & 0xffffffff, s["name"]) for s in syms if s.get("type") == "FUNC")
    faddr = [a for a, _ in funcs]
    byaddr = {a: n for a, n in funcs}

    def encl(pc):
        i = bisect.bisect_right(faddr, pc) - 1
        return funcs[i][1] if i >= 0 else None

    callees = collections.defaultdict(set)
    for fl, addr, off, sz in secs:
        if not (fl & 0x4) or not addr:
            continue
        blob = d[off:off + sz]
        for j in range(0, len(blob) - 3, 4):
            w = struct.unpack(">I", blob[j:j + 4])[0]
            op = w >> 26
            if op == 0x03:  # jal
                tgt = ((addr + j) & 0xf0000000) | ((w & 0x03ffffff) << 2)
                callee = byaddr.get(tgt)
                if callee:
                    caller = encl(addr + j)
                    if caller and caller != callee:
                        callees[caller].add(callee)
    cg = {k: sorted(v) for k, v in callees.items()}
    callers = collections.defaultdict(list)
    for c, cs in cg.items():
        for x in cs:
            callers[x].append(c)
    json.dump({"callees": cg, "callers": {k: sorted(v) for k, v in callers.items()}},
              open(CG, "w"))
    print(f"built call graph: {len(cg)} functions with direct callees -> {CG}")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"
    if cmd == "build":
        build(); return
    g = json.load(open(CG))
    if cmd == "callees":
        for x in g["callees"].get(sys.argv[2], []):
            print("  " + x)
    elif cmd == "callers":
        for x in g["callers"].get(sys.argv[2], []):
            print("  " + x)
    elif cmd == "path":
        src, dst = sys.argv[2], sys.argv[3]
        q = collections.deque([[src]]); seen = {src}
        while q:
            p = q.popleft()
            if p[-1] == dst:
                print(" -> ".join(p)); return
            for nx in g["callees"].get(p[-1], []):
                if nx not in seen:
                    seen.add(nx); q.append(p + [nx])
        print(f"no direct-call path {src} -> {dst} (may be via function pointer)")


if __name__ == "__main__":
    main()
