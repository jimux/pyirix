#!/usr/bin/env python3
"""Find callers of a kernel function by scanning .text for `jal <target>`.
Static; resolves caller PCs to the enclosing function via golden symbols."""
import json, struct, sys, bisect, os
ELF = os.environ.get("KELF", "/workspace/_golden_extract/unix")
SYMS = os.environ.get("KSYMS", "/workspace/ip54_kernel_symbols_golden.json")


def load_text(elf):
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
        e = d[shoff+i*es: shoff+(i+1)*es]
        if is64:
            addr=struct.unpack(">Q",e[0x10:0x18])[0]; off=struct.unpack(">Q",e[0x18:0x20])[0]; sz=struct.unpack(">Q",e[0x20:0x28])[0]
        else:
            addr=struct.unpack(">I",e[0x0c:0x10])[0]; off=struct.unpack(">I",e[0x10:0x14])[0]; sz=struct.unpack(">I",e[0x14:0x18])[0]
        flags = struct.unpack(">Q" if is64 else ">I", e[(0x08 if is64 else 0x08):(0x10 if is64 else 0x0c)])[0]
        secs.append((addr & 0xffffffff, off, sz))
    return d, secs


def main():
    target_name = sys.argv[1]
    syms = json.load(open(SYMS))
    byname = {s["name"]: s["address"] & 0xffffffff for s in syms}
    funcs = sorted((s["address"] & 0xffffffff, s["name"]) for s in syms if s.get("type")=="FUNC")
    addrs = [a for a,_ in funcs]
    target = byname[target_name]
    jal = 0x0C000000 | ((target >> 2) & 0x03FFFFFF)
    jal_be = struct.pack(">I", jal)
    d, secs = load_text(ELF)
    def encl(pc):
        i = bisect.bisect_right(addrs, pc) - 1
        return funcs[i][1] if i>=0 else "?"
    print(f"=== callers of {target_name} @ 0x{target:08x} (jal=0x{jal:08x}) ===")
    hits = []
    for base, off, sz in secs:
        if base < 0x88000000 or base >= 0x88400000:  # text-ish
            continue
        blob = d[off:off+sz]
        idx = 0
        while True:
            j = blob.find(jal_be, idx)
            if j < 0: break
            if j % 4 == 0:
                pc = base + j
                hits.append(pc)
            idx = j + 1
    for pc in sorted(set(hits)):
        print(f"  0x{pc:08x}  in {encl(pc)}")
    print(f"total call sites: {len(set(hits))}")


if __name__ == "__main__":
    main()
