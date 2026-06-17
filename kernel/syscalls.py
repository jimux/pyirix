#!/usr/bin/env python3
"""ksyscalls — inventory ioctl command constants referenced in a MIPS ELF and
decode them (IRIX _IO* encoding), mapping each to the function that uses it.
Catches the distinctive _IO-encoded cmds (idev 'i', shmiq/qcntl 'Q', etc.) loaded
via lui+ori; small GFX_* ints are reported separately if loaded to $a1.

  KELF=/workspace/xsgi.bin KSYMS=/workspace/xsgi_symbols.json python3 ksyscalls.py
  ... python3 ksyscalls.py --func <fn>     # ioctls used by one function
"""
import json, struct, sys, bisect, os

ELF = os.environ.get("KELF", "/workspace/_golden_extract/unix")
SYMS = os.environ.get("KSYMS", "/workspace/ip54_kernel_symbols_golden.json")

# IRIX ioctl direction bits
IOC_VOID = 0x20000000; IOC_OUT = 0x40000000; IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT


def decode(cmd):
    d = cmd & 0xe0000000
    dirs = {IOC_VOID: "IO", IOC_OUT: "IOR", IOC_IN: "IOW", IOC_INOUT: "IOWR"}.get(d, "?")
    size = (cmd >> 16) & 0xff   # IOCPARM_MASK=0xff (sys/ioccom.h), <256 bytes
    typ = (cmd >> 8) & 0xff
    nr = cmd & 0xff
    tc = chr(typ) if 32 <= typ < 127 else "?"
    return f"_{dirs}('{tc}',{nr},sz={size})"


def is_ioctl(cmd):
    if (cmd & 0xe0000000) not in (IOC_VOID, IOC_OUT, IOC_IN, IOC_INOUT):
        return False
    if cmd & 0x1f000000:        # bits 24-28 must be 0 (size is only bits 16-23)
        return False
    typ = (cmd >> 8) & 0xff
    return 32 <= typ < 127      # printable ioctl group char


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


def main():
    func_filter = None
    if len(sys.argv) > 2 and sys.argv[1] == "--func":
        func_filter = sys.argv[2]
    d, secs = load(ELF)
    syms = json.load(open(SYMS))
    funcs = sorted((s["address"] & 0xffffffff, s["name"]) for s in syms if s.get("type") == "FUNC")
    faddr = [a for a, _ in funcs]

    def encl(pc):
        i = bisect.bisect_right(faddr, pc) - 1
        return funcs[i][1] if i >= 0 else "?"

    found = {}  # cmd -> set(funcs)
    for fl, addr, off, sz in secs:
        if not (fl & 0x4) or not addr:
            continue
        blob = d[off:off + sz]
        hi = {}
        for j in range(0, len(blob) - 3, 4):
            w = struct.unpack(">I", blob[j:j + 4])[0]
            op = w >> 26
            if op == 0x0f:  # lui
                hi[(w >> 16) & 0x1f] = (w & 0xffff) << 16
            elif op == 0x0d:  # ori rt,rs,imm
                rs = (w >> 21) & 0x1f
                if rs in hi:
                    cmd = (hi[rs] | (w & 0xffff)) & 0xffffffff
                    if is_ioctl(cmd):
                        found.setdefault(cmd, set()).add(encl(addr + j))

    rows = sorted(found.items())
    if func_filter:
        rows = [(c, fs) for c, fs in rows if func_filter in fs]
    for cmd, fs in rows:
        print("  0x%08x  %-22s <- %s" % (cmd, decode(cmd), ", ".join(sorted(fs)[:5])))
    print("total distinct ioctl cmds: %d" % len(rows))


if __name__ == "__main__":
    main()
