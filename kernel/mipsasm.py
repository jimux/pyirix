#!/usr/bin/env python3
"""mipsasm.py -- assemble MIPS asm -> big-endian instruction words for PROM trampolines.

Task C3 (#33): kills the hand-encoding bug class (e.g. the lw $t9 used $k0 not $t2
encoding bug found via GDB in the interrupt-wiring work, #21). Instead of writing raw
0x8D5900A0 words by hand into prom-building/src/fw/ip54_stubs.c, write the trampoline
in real assembly and let the cross-assembler encode it.

Pipeline (matches the C3 spec):
    mips-elf-as  -march=mips3 -mabi=32 -EB -G 0  -o t.o  t.s
    mips-elf-objcopy -O binary t.o t.bin
    unpack big-endian u32 words from t.bin

The cross toolchain lives in the docker dev container (/opt/cross/mips-elf/bin). This
script auto-detects whether it is already inside the container; if not, it re-runs the
assemble step via `docker compose exec -T dev`.

Usage:
    # from a .s file, emit C `p[i] =` assignments ready to paste into a trampoline
    python3 mipsasm.py tramp.s --p-array p

    # from stdin, emit a named C array
    echo 'lui $t2,0x8806 ; ori $t2,$t2,0x4854 ; jr $t2 ; nop' | python3 mipsasm.py - --c-array tramp_words

    # just the hex words, one per line
    python3 mipsasm.py tramp.s

As a library:
    from mipsasm import assemble
    words = assemble("lw $t9, 0xa0($t2)\\njr $t9\\nnop")   # -> [0x8d4900a0, 0x03200008, 0x00000000]
"""
import os
import sys
import struct
import subprocess
import tempfile

MARCH = "mips3"
ABI = "32"
ENDIAN = "EB"          # big-endian (SGI)
GVAL = "0"             # -G 0: no small-data / GP-relative
CROSS = "/opt/cross/mips-elf/bin"
AS = f"{CROSS}/mips-elf-as"
OBJCOPY = f"{CROSS}/mips-elf-objcopy"


def _in_container() -> bool:
    return os.path.exists("/opt/cross/mips-elf/bin/mips-elf-as")


def _assemble_in_container(asm_text: str, march: str, abi: str, endian: str, gval: str) -> bytes:
    """Run as+objcopy locally (we are inside the dev container). Returns the raw .text bytes."""
    with tempfile.TemporaryDirectory() as d:
        s = os.path.join(d, "t.s")
        o = os.path.join(d, "t.o")
        b = os.path.join(d, "t.bin")
        with open(s, "w") as f:
            # .set noreorder so the assembler never reorders/inserts nops behind our back --
            # trampolines are layout-sensitive (the delay slot must be exactly what we wrote).
            f.write(".set noreorder\n.set noat\n")
            f.write(asm_text)
            if not asm_text.endswith("\n"):
                f.write("\n")
        r = subprocess.run(
            [AS, f"-march={march}", f"-mabi={abi}", f"-{endian}", f"-G{gval}", "-o", o, s],
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        if r.returncode != 0:
            raise RuntimeError("mips-elf-as failed:\n" + r.stderr.decode(errors="replace"))
        r = subprocess.run(
            [OBJCOPY, "-O", "binary", "-j", ".text", o, b],
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        if r.returncode != 0:
            raise RuntimeError("mips-elf-objcopy failed:\n" + r.stderr.decode(errors="replace"))
        with open(b, "rb") as f:
            return f.read()


def _assemble_via_docker(asm_text: str, march: str, abi: str, endian: str, gval: str) -> bytes:
    """We are on the host -- re-run ourselves inside the dev container and capture the words."""
    repo = os.path.dirname(os.path.abspath(__file__))
    # Pass the asm on stdin to a one-liner that imports this very module inside the container.
    pyprog = (
        "import sys; sys.path.insert(0,'/workspace'); import mipsasm; "
        "import struct; "
        f"b=mipsasm._assemble_in_container(sys.stdin.read(),'{march}','{abi}','{endian}','{gval}'); "
        "sys.stdout.write(' '.join('%08x'%w for w in struct.unpack('>%dI'%(len(b)//4), b)))"
    )
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "dev", "python3", "-c", pyprog],
        input=asm_text.encode(), cwd=repo,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if r.returncode != 0:
        raise RuntimeError("docker assemble failed:\n" + r.stderr.decode(errors="replace"))
    out = r.stdout.decode().strip()
    if not out:
        return b""
    return struct.pack(">%dI" % len(out.split()), *(int(w, 16) for w in out.split()))


def assemble(asm_text: str, march: str = MARCH, abi: str = ABI,
             endian: str = ENDIAN, gval: str = GVAL):
    """Assemble MIPS source and return a list of big-endian 32-bit instruction words."""
    raw = (_assemble_in_container if _in_container() else _assemble_via_docker)(
        asm_text, march, abi, endian, gval)
    if len(raw) % 4:
        raise RuntimeError(f"assembled .text is {len(raw)} bytes, not word-aligned")
    return list(struct.unpack(">%dI" % (len(raw) // 4), raw))


def emit_c_array(words, name):
    lines = [f"static const unsigned int {name}[{len(words)}] = {{"]
    for i, w in enumerate(words):
        lines.append(f"    0x{w:08x}U,   /* [{i}] */")
    lines.append("};")
    return "\n".join(lines)


def emit_p_array(words, ptr):
    return "\n".join(f"{ptr}[{i}] = 0x{w:08x}U;" for i, w in enumerate(words))


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Assemble MIPS asm -> PROM trampoline words")
    ap.add_argument("source", help="path to a .s file, or '-' for stdin")
    ap.add_argument("--c-array", metavar="NAME", help="emit a `static const unsigned int NAME[] = {...}`")
    ap.add_argument("--p-array", metavar="PTR", help="emit `PTR[i] = 0x...;` assignments (trampoline style)")
    ap.add_argument("--march", default=MARCH)
    ap.add_argument("--abi", default=ABI)
    ap.add_argument("--endian", default=ENDIAN)
    ap.add_argument("--gval", default=GVAL)
    a = ap.parse_args(argv)

    asm_text = sys.stdin.read() if a.source == "-" else open(a.source).read()
    words = assemble(asm_text, a.march, a.abi, a.endian, a.gval)

    if a.c_array:
        print(emit_c_array(words, a.c_array))
    elif a.p_array:
        print(emit_p_array(words, a.p_array))
    else:
        for w in words:
            print(f"0x{w:08x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
