#!/usr/bin/env python3
"""kstrings — resolve absolute (lui+addiu/ori) string/data references in a MIPS
ELF and report which FUNCTION references each string. Works on ET_EXEC absolute
addressing (Xsgi uses lui/addiu, not GOT). Static, no QEMU.

  KELF=/workspace/xsgi.bin KSYMS=/workspace/xsgi_symbols.json \
    python3 kstrings.py                 # dump all string refs grouped by string
  ... python3 kstrings.py <substr>      # only refs whose string contains <substr>
  ... python3 kstrings.py --func <fn>   # only refs made by function <fn>
"""
import json, struct, sys, bisect, os

ELF = os.environ.get("KELF", "/workspace/_golden_extract/unix")
SYMS = os.environ.get("KSYMS", "/workspace/ip54_kernel_symbols_golden.json")


def load(elf):
    d = open(elf, "rb").read()
    is64 = d[4] == 2
    if is64:
        shoff = struct.unpack(">Q", d[0x28:0x30])[0]
        es = struct.unpack(">H", d[0x3a:0x3c])[0]; n = struct.unpack(">H", d[0x3c:0x3e])[0]
    else:
        shoff = struct.unpack(">I", d[0x20:0x24])[0]
        es = struct.unpack(">H", d[0x2e:0x30])[0]; n = struct.unpack(">H", d[0x30:0x32])[0]
    secs = []
    for i in range(n):
        e = d[shoff + i * es: shoff + (i + 1) * es]
        if is64:
            flags = struct.unpack(">Q", e[0x08:0x10])[0]
            addr = struct.unpack(">Q", e[0x10:0x18])[0]; off = struct.unpack(">Q", e[0x18:0x20])[0]; sz = struct.unpack(">Q", e[0x20:0x28])[0]
        else:
            flags = struct.unpack(">I", e[0x08:0x0c])[0]
            addr = struct.unpack(">I", e[0x0c:0x10])[0]; off = struct.unpack(">I", e[0x10:0x14])[0]; sz = struct.unpack(">I", e[0x14:0x18])[0]
        secs.append({"flags": flags, "addr": addr & 0xffffffff, "off": off, "sz": sz})
    return d, secs


def main():
    args = sys.argv[1:]
    func_filter = None
    if args and args[0] == "--func":
        func_filter = args[1]; args = args[2:]
    substr = args[0] if args else None

    d, secs = load(ELF)
    syms = json.load(open(SYMS))
    funcs = sorted((s["address"] & 0xffffffff, s["name"]) for s in syms if s.get("type") == "FUNC")
    faddr = [a for a, _ in funcs]

    def encl(pc):
        i = bisect.bisect_right(faddr, pc) - 1
        return funcs[i][1] if i >= 0 else "?"

    text = [s for s in secs if (s["flags"] & 0x4) and s["addr"]]      # EXECINSTR
    data = [s for s in secs if (s["flags"] & 0x2) and s["addr"]]      # ALLOC

    def readstr(va):
        for s in data:
            if s["addr"] <= va < s["addr"] + s["sz"]:
                p = s["off"] + (va - s["addr"]); e = p
                while e < s["off"] + s["sz"] and d[e] != 0 and (e - p) < 200:
                    e += 1
                raw = d[p:e]
                if raw and all(9 <= c < 127 for c in raw):
                    return raw.decode("latin1")
        return None

    refs = []  # (func, instr_va, string)
    for s in text:
        hi = {}  # reg -> (hi_value<<16, lui_va)
        base = s["addr"]; blob = d[s["off"]:s["off"] + s["sz"]]
        for j in range(0, len(blob) - 3, 4):
            w = struct.unpack(">I", blob[j:j + 4])[0]
            op = w >> 26
            va = base + j
            if op == 0x0f:                      # lui rt, imm
                rt = (w >> 16) & 0x1f
                hi[rt] = ((w & 0xffff) << 16, va)
            elif op in (0x09, 0x0d):            # addiu/ori rt, rs, imm
                rs = (w >> 21) & 0x1f; rt = (w >> 16) & 0x1f; imm = w & 0xffff
                if rs in hi:
                    hv = hi[rs][0]
                    addr = (hv + (imm - 0x10000 if (op == 0x09 and imm & 0x8000) else imm)) & 0xffffffff
                    st = readstr(addr)
                    if st:
                        refs.append((encl(hi[rs][1]), va, st))
                    if rt != rs:
                        hi.pop(rt, None)        # rt now holds an address, not a hi
            else:
                # crude: a store/other op doesn't invalidate; keep it simple
                pass

    # output
    if func_filter:
        out = [(f, v, s) for (f, v, s) in refs if f == func_filter]
        for f, v, s in out:
            print("  0x%08x  %r" % (v, s))
        print("total: %d string refs by %s" % (len(out), func_filter))
        return
    # group by string
    bystr = {}
    for f, v, s in refs:
        if substr and substr not in s:
            continue
        bystr.setdefault(s, set()).add(f)
    for s in sorted(bystr):
        fns = sorted(bystr[s])
        print("%-44r  <- %s" % (s, ", ".join(fns[:6]) + (" …+%d" % (len(fns) - 6) if len(fns) > 6 else "")))
    print("total distinct strings: %d" % len(bystr))


if __name__ == "__main__":
    main()
