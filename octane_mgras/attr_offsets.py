#!/usr/bin/env python3
"""Widget-base dataflow over a MIPS disassembly: which instruction computes widget+N.

The MGRAS widget is 16 MB of MMIO at the top of the IP30 address space.  A kernel
accessor reaches a register either as a literal (`lui`+`ori`) or, far more often,
as `widget_base + WIN` where `WIN` is a window constant and `widget_base` is the
pointer the driver was handed.  Reading the offset off the trace tells you a
register was touched; only this dataflow tells you WHICH FUNCTION touched it,
which is the naming witness (`MgrasInitDac` writing +0x71890 says what the DAC
block is for; the trace alone does not).

THE FAILURE MODE IS "NO NAME", NEVER "WRONG NAME".  The rules, deliberately
conservative, are the parent lanes' and are carried here verbatim:

  * an argument register (a0..a3) that the function has not yet overwritten is
    the widget base -- opaque, provenance "arg";
  * `ld r,208(aN)` is the device base, provenance "hwbase", and so is the
    two-step `ld ctx,0(aN)` / `ld hw,208(ctx)` the kernel uses;
  * `arg + arg` has no proven constant and is DROPPED (this is why
    MgrasSetColors' `daddu s7,a2,s6` cannot be attributed on the path where the
    constant is not established);
  * a base spilled to and reloaded from the stack (`ld a1,56(sp)`) LOSES its
    provenance: a load through `sp` yields nothing, so MgrasFlushHQ3's
    +0x40080/+0x40088 are refused and stay refused;
  * a base reached only through sp/gp/fp/ra is never attributed;
  * a register a `jal` may have clobbered is dropped, not carried;
  * only the context offsets 0 and 208 are followed; every other load is opaque;
  * anything the scan cannot follow is dropped rather than guessed.

Public surface (the map builder and the tests both use it):

    parse_disassembly(lines)          -> [Insn]
    attribute(insns, targets=None)    -> {offset: [Hit]}
    attribute_text(text, targets)     -> same, from a string
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

#: The widget is 16 MB; anything an accessor computes outside this is not a
#: widget register and is dropped (a real address outside the window is the
#: map's negative control).
WINDOW_MIN = 0x0
WINDOW_MAX = 0x140000

ARGS = frozenset(("a0", "a1", "a2", "a3"))
#: Registers a callee may clobber; after a `jal` their contents are unknown.
CALLER_SAVED = frozenset(("a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
                          "t5", "t6", "t7", "t8", "t9", "v0", "v1", "at", "ra"))
#: Registers that are never a widget base: the stack, globals, the frame pointer.
NEVER_BASE = frozenset(("sp", "gp", "fp", "s8", "ra", "zero", "at"))

LOAD_MNEMS = {"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "ll", "lld"}
STORE_MNEMS = {"sb", "sh", "sw", "sd", "sc", "scd"}

#: Byte width of each access mnemonic, for `width` in the map.
WIDTH = {"sb": 1, "lb": 1, "lbu": 1, "sh": 2, "lh": 2, "lhu": 2,
         "sw": 4, "lw": 4, "lwu": 4, "ll": 4, "sc": 4,
         "sd": 8, "ld": 8, "lld": 8, "scd": 8}

#: Instructions that read registers without writing one of them.
PURE_READ = {"beq", "bne", "beqz", "bnez", "b", "bal", "jr", "jal", "jalr", "j",
             "nop", "sltiu", "sltu", "slt", "slti", "andi", "xori", "bgez",
             "bgezal", "bltz", "bltzal", "blez", "bgtz", "beql", "bnel", "movz",
             "movn", "teq", "tne", "ssnop", "sync"}

#: `a8000000202afb34:   afa20000   sw  v0,7936(a5)` -- objdump -d, MIPS.
INSN_RX = re.compile(r"^([0-9a-f]{8,16}):\s+([0-9a-f]+)\s+(\S+)\s*(.*)$")
SYM_RX = re.compile(r"^([0-9a-f]{8,16})\s+<([^>]+)>:")
MEM_RX = re.compile(r"^(-?(?:0x)?[0-9a-f]+)?\((\$?\w+)\)$")


def _reg(r: str) -> str:
    return r.lstrip("$")


@dataclass
class Insn:
    addr: int
    mnem: str
    args: list
    sym: str = ""

    @property
    def is_mem(self) -> bool:
        return self.mnem in LOAD_MNEMS or self.mnem in STORE_MNEMS

    @property
    def dir(self) -> str:
        return "w" if self.mnem in STORE_MNEMS else "r"


@dataclass
class Hit:
    """One instruction that computes a widget offset."""

    offset: int
    func: str
    addr: int
    insn: str
    dir: str
    width: int
    provenance: str
    base_reg: str = ""

    def as_evidence(self) -> dict:
        return {"insn": "%x" % self.addr, "function": self.func,
                "text": self.insn, "provenance": self.provenance,
                "dir": self.dir, "width": self.width}


def parse_disassembly(lines) -> list:
    """objdump -d output -> [Insn], each carrying the symbol it sits inside."""
    out = []
    sym = ""
    for line in lines:
        m = SYM_RX.match(line.strip())
        if m:
            # `MgrasVerifyVC3SRAM+0x11c` is still inside MgrasVerifyVC3SRAM
            sym = m.group(2).split("+")[0]
            continue
        m = INSN_RX.match(line.rstrip("\n"))
        if not m:
            continue
        body = m.group(4).split("<")[0].strip()
        parts = [p.strip() for p in body.split(",")] if body else []
        out.append(Insn(int(m.group(1), 16), m.group(3), parts, sym))
    return out


class _Val:
    """A symbolic register value: a known constant above a known base."""

    __slots__ = ("const", "base", "provenance")

    def __init__(self, const: int = 0, base: str = "", provenance: str = "const"):
        self.const = const
        self.base = base
        self.provenance = provenance

    def __repr__(self) -> str:
        return "_Val(%#x, %r, %r)" % (self.const, self.base, self.provenance)


def _imm(tok: str):
    tok = tok.strip()
    neg = tok.startswith("-")
    if neg:
        tok = tok[1:]
    try:
        v = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 0)
    except ValueError:
        return None
    return -v if neg else v


def attribute(insns: list, targets=None) -> dict:
    """Every widget offset the widget-base dataflow can attribute, with its writer.

    *targets*, when given, restricts the RESULT to those offsets (the traced
    path), but never the scan: a control asks about an offset that is not in the
    target list and gets whatever the dataflow really finds, or nothing.
    """
    want = {t & 0xFFFFFFFF for t in targets} if targets is not None else None
    hits: dict = {}
    regs: dict = {}
    live: set = set()       # argument registers the function has not overwritten
    func = None

    def add(off: int, insn: Insn, prov: str, base_reg: str) -> None:
        off &= 0xFFFFFFFF
        if not (WINDOW_MIN <= off < WINDOW_MAX):
            return
        if want is not None and off not in want:
            return
        hits.setdefault(off, []).append(Hit(
            off, func or "?", insn.addr,
            "%s %s" % (insn.mnem, ", ".join(insn.args)),
            insn.dir, WIDTH.get(insn.mnem, 0), prov, base_reg))

    for insn in insns:
        mn, a = insn.mnem, insn.args
        if insn.sym != func:            # a function boundary restarts the dataflow
            func = insn.sym
            regs = {}
            live = set(ARGS)
        dst = _reg(a[0]) if a else ""

        if mn in ("jal", "jalr", "bal"):
            for r in CALLER_SAVED:
                regs.pop(r, None)
                live.discard(r)
            continue

        if mn == "lui" and len(a) == 2:
            v = _imm(a[1])
            regs[dst] = _Val(0 if v is None else (v << 16) & 0xFFFFFFFF)
            live.discard(dst)
            continue

        if mn in ("ori", "addiu", "daddiu", "addi", "daddi", "li") and len(a) == 3:
            src, im = _reg(a[1]), _imm(a[2])
            prev = _Val() if src == "zero" else regs.get(src)
            if im is None or (prev is None and src != "zero"):
                regs.pop(dst, None)
            elif mn == "li" or src == "zero" or not prev.base:
                base = prev or _Val()
                regs[dst] = _Val((base.const + im) & 0xFFFFFFFF)
            else:
                regs[dst] = _Val(prev.const + im, prev.base, prev.provenance)
            live.discard(dst)
            continue

        if mn in ("daddu", "addu", "dadd", "add", "or") and len(a) == 3:
            s, t = _reg(a[1]), _reg(a[2])
            vs, vt = regs.get(s), regs.get(t)
            s_arg, t_arg = s in live, t in live
            # `lui r,WIN` then `daddu base,arg,r`: the constant sits in one
            # source and the widget-base argument (or hwbase) in the other
            if s_arg and vt is not None and not vt.base and not t_arg:
                regs[dst] = _Val(vt.const, "arg", "arg")
            elif t_arg and vs is not None and not vs.base and not s_arg:
                regs[dst] = _Val(vs.const, "arg", "arg")
            elif s_arg and not t_arg and vt is not None and vt.base:
                regs[dst] = _Val(vt.const, vt.base, vt.provenance)
            elif t_arg and not s_arg and vs is not None and vs.base:
                regs[dst] = _Val(vs.const, vs.base, vs.provenance)
            elif s_arg and not t_arg:
                regs[dst] = _Val(0, "arg", "arg")
            elif t_arg and not s_arg:
                regs[dst] = _Val(0, "arg", "arg")
            elif vs is not None and vt is not None and vs.base and vt.base:
                regs.pop(dst, None)     # arg + arg: no proven constant
            elif vs is not None and vs.base and vt is not None and not vt.base:
                regs[dst] = _Val(vs.const + vt.const, vs.base, vs.provenance)
            elif vt is not None and vt.base and vs is not None and not vs.base:
                regs[dst] = _Val(vt.const + vs.const, vt.base, vt.provenance)
            elif vs is not None and vt is not None and not vs.base and not vt.base:
                regs[dst] = _Val((vs.const + vt.const) & 0xFFFFFFFF)
            else:
                regs.pop(dst, None)
            live.discard(dst)
            continue

        if mn in ("move", "dmove") and len(a) == 2:
            src = _reg(a[1])
            if src in live:
                regs[dst] = _Val(0, "arg", "arg")
            elif src in regs:
                regs[dst] = regs[src]
            else:
                regs.pop(dst, None)
            live.discard(dst)
            continue

        if insn.is_mem and len(a) == 2:
            m = MEM_RX.match(a[1].replace(" ", ""))
            if not m:
                regs.pop(dst, None)
                live.discard(dst)
                continue
            imm = _imm(m.group(1)) if m.group(1) else 0
            base = _reg(m.group(2))
            v = regs.get(base)
            if insn.dir == "r" and imm == 0 and base in live:
                # `ld ctx,0(aN)`: step one of the context-pointer idiom
                regs[dst] = _Val(0, "ctx", "ctx")
                live.discard(dst)
                continue
            if (insn.dir == "r" and imm == 208
                    and (base in live or (v is not None and v.base == "ctx"))):
                # `ld r,208(aN)` / `ld hw,208(ctx)`: the device base
                regs[dst] = _Val(0, "hwbase", "hwbase")
                live.discard(dst)
                continue
            if v is not None and v.base in ("arg", "hwbase") and imm is not None:
                add(v.const + imm, insn, v.provenance, base)
            if insn.dir == "r":
                regs[dst] = _Val()       # a loaded value is opaque
                live.discard(dst)
            continue

        if dst and mn not in PURE_READ and dst not in NEVER_BASE:
            regs.pop(dst, None)
            live.discard(dst)
    return hits


def attribute_text(text: str, targets=None) -> dict:
    return attribute(parse_disassembly(text.splitlines()), targets)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dis", nargs="?", default="tmp/unix.dis")
    ap.add_argument("--targets", help="comma-separated offsets (hex ok)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    targets = None
    if args.targets:
        targets = [int(t, 0) for t in args.targets.replace(" ", "").split(",") if t]
    text = Path(args.dis).read_text(errors="replace")
    hits = attribute_text(text, targets)
    if args.json:
        print(json.dumps({("%x" % k): [h.as_evidence() for h in v]
                          for k, v in sorted(hits.items())}, indent=1))
        return 0
    for off in sorted(hits):
        first = hits[off][0]
        print("0x%06x %-24s %x  %-28s %s" % (off, first.func, first.addr,
                                             first.insn, first.provenance))
    print("%d offset(s) attributed over %s" % (len(hits), args.dis))
    return 0


if __name__ == "__main__":
    sys.exit(main())
