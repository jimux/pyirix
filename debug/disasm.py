#!/usr/bin/env python3
"""Disassemble a kernel function by name from a kernel ELF (capstone MIPS64/BE),
resolving jal/branch targets against the golden symbol JSON. Static, no QEMU."""
import json, struct, sys, os

from .mips_disasm import MipsDisassembler

# Override with env: KELF=/workspace/xsgi.bin KSYMS=/workspace/xsgi_symbols.json
ELF = os.environ.get("KELF", "/workspace/_golden_extract/unix")
SYMS = os.environ.get("KSYMS", "/workspace/ip54_kernel_symbols_golden.json")


def load_text(elf):
    d = open(elf, "rb").read()
    # ELF32 BE (n32). e_shoff at 0x20, e_shentsize 0x2e, e_shnum 0x30, shstrndx 0x32
    is64 = d[4] == 2
    if is64:
        shoff = struct.unpack(">Q", d[0x28:0x30])[0]
        shentsize = struct.unpack(">H", d[0x3a:0x3c])[0]
        shnum = struct.unpack(">H", d[0x3c:0x3e])[0]
    else:
        shoff = struct.unpack(">I", d[0x20:0x24])[0]
        shentsize = struct.unpack(">H", d[0x2e:0x30])[0]
        shnum = struct.unpack(">H", d[0x30:0x32])[0]
    secs = []
    for i in range(shnum):
        e = d[shoff + i * shentsize: shoff + (i + 1) * shentsize]
        if is64:
            addr = struct.unpack(">Q", e[0x10:0x18])[0]
            off = struct.unpack(">Q", e[0x18:0x20])[0]
            size = struct.unpack(">Q", e[0x20:0x28])[0]
        else:
            addr = struct.unpack(">I", e[0x0c:0x10])[0]
            off = struct.unpack(">I", e[0x10:0x14])[0]
            size = struct.unpack(">I", e[0x14:0x18])[0]
        secs.append((addr, off, size))
    return d, secs


def main():
    name = sys.argv[1]
    syms = json.load(open(SYMS))
    byname = {s["name"]: s for s in syms}
    addr2name = sorted((s["address"] & 0xffffffff, s["name"]) for s in syms
                       if s.get("type") == "FUNC")
    s = byname[name]
    va = s["address"] & 0xffffffff
    size = s["size"] or 256
    d, secs = load_text(ELF)
    foff = None
    for addr, off, sz in secs:
        a = addr & 0xffffffff
        if a <= va < a + sz:
            foff = off + (va - a); break
    if foff is None:
        print("VA not in any section"); return
    code = d[foff:foff + size]
    dis = MipsDisassembler(mode="mips3")
    import bisect
    addrs = [a for a, _ in addr2name]

    def resolve(t):
        i = bisect.bisect_right(addrs, t & 0xffffffff) - 1
        if i < 0:
            return ""
        base, nm = addr2name[i][0], addr2name[i][1]
        off = (t & 0xffffffff) - base
        return f"{nm}+0x{off:x}" if off else nm

    print(f"=== {name} @ 0x{va:08x} ({size} bytes) ===")
    for ln in dis.disassemble(code, va, annotate=True):
        tgt = ""
        if ln.mnemonic in ("jal", "j", "bal") and ln.branch_target:
            tgt = "  -> " + resolve(ln.branch_target)
        print(f"  0x{ln.address:08x}  {ln.mnemonic:8} {ln.op_str}{tgt}")


if __name__ == "__main__":
    main()
