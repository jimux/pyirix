"""Def-use / register-propagation symbolication for MIPS PROM images.

The problem this solves: a PROM like the IP27 image reaches its data through
**register data-flow**, not per-literal immediates.  Addresses are built by
``lui``/``dsll``/``daddiu`` chains into a high segment (e.g.
``0xc0001fc74800``), and string/data bases are often a register computed once
or loaded from a table.  So scanning for the constant of a string's address
finds nothing; the reference has to be recovered by propagating the register
value forward from function entry.

This module abstracts over a function's control flow tracking each GPR as one
of:

* ``UNKNOWN`` -- clobbered, loaded, or an indirect result;
* a **known constant** (int) -- any arithmetic result of true constants;
* ``("rel", base, off)`` -- base-relative where ``base`` is not yet known.

When a register becomes a known constant that lies inside a supplied data
**window**, that is a reference to the window; the enclosing function (the
entry whose span contains the site) is the symbolication answer.

Doctrine: a value derived from an ``UNKNOWN`` base is reported **unresolved**,
never guessed.  ``resolve_anchors`` returns both the hits and the unresolved
set so nothing is silently dropped.

The decoder is deliberately small: only the instruction families that matter
for address formation and control flow.  Anything else clobbers its
destination to ``UNKNOWN`` (safe) which keeps false positives out.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

UNKNOWN = None  # a register whose value we cannot prove

# --- MIPS register ABI (o32/n32/n64 numbering is the same for these) ---------
ZERO, AT, V0, V1 = 0, 1, 2, 3
A0, A1, A2, A3 = 4, 5, 6, 7
T0, T1, T2, T3 = 8, 9, 10, 11
S0, S1, S2, S3 = 16, 17, 18, 19
RA = 31
SP = 29
GP = 28

CALLER_SAVED = frozenset([AT, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3, 12, 13, 14, 15, 24, 25])
CALLEE_SAVED = frozenset([S0, S1, S2, S3, 20, 21, 22, 23, GP, SP, 30])


# --------------------------------------------------------------------------- #
# Instruction decoding (the subset that matters)
# --------------------------------------------------------------------------- #
def _op(w: int) -> int:
    return (w >> 26) & 0x3F


def _rs(w: int) -> int:
    return (w >> 21) & 0x1F


def _rt(w: int) -> int:
    return (w >> 16) & 0x1F


def _rd(w: int) -> int:
    return (w >> 11) & 0x1F


def _sa(w: int) -> int:
    return (w >> 6) & 0x1F


def _fn(w: int) -> int:
    return w & 0x3F


def _simm(w: int) -> int:
    v = w & 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


def _uimm(w: int) -> int:
    return w & 0xFFFF


def _jtarget(w: int, pc: int) -> int:
    return (pc & 0xF0000000) | ((w & 0x03FFFFFF) << 2)


def _branch_target(w: int, pc: int) -> int:
    return pc + 4 + (_simm(w) << 2)


@dataclass
class Slice:
    """A code slice with a VA<->file-offset mapping and word endianness."""

    code: bytes
    code_off: int          # file offset of the first code byte
    va_base: int           # VA of the first code byte
    big_endian: bool = True

    def word(self, va: int) -> Optional[int]:
        off = va - self.va_base
        if off < 0 or off + 4 > len(self.code):
            return None
        fmt = ">I" if self.big_endian else "<I"
        return struct.unpack_from(fmt, self.code, off)[0]

    def contains(self, va: int) -> bool:
        off = va - self.va_base
        return 0 <= off < len(self.code)

    @property
    def va_end(self) -> int:
        return self.va_base + len(self.code)


# --------------------------------------------------------------------------- #
# Abstract interpretation
# --------------------------------------------------------------------------- #
@dataclass
class Ref:
    """A recovered reference: a site whose register became a window constant."""

    site: int              # VA of the instruction that established the value
    reg: int               # register holding the value
    value: int             # the resolved constant
    function: int          # VA of the enclosing function entry


def _join(a, b):
    """Merge two abstract values at a control-flow join."""
    if a == b:
        return a
    return UNKNOWN


def _entry_successors(w: int, pc: int) -> List[int]:
    """Successor PCs for control flow (includes the return edge of a call)."""
    op = _op(w)
    nxt = pc + 4
    if op in (0x02, 0x03):            # j / jal (jump to target; jal returns)
        t = _jtarget(w, pc)
        return [t, nxt] if op == 0x03 else [t]
    if op in (0x04, 0x05, 0x06, 0x07, 0x01):  # beq/bne/blez/bgtz/bltz-family
        return [nxt, _branch_target(w, pc)]
    if op == 0:                        # SPECIAL
        fn = _fn(w)
        if fn == 0x08:                 # jr
            return []
        if fn == 0x09:                 # jalr
            return [nxt]
    return [nxt]


def propagate_function(
    sl: Slice,
    entry: int,
    entries: frozenset,
    window: Tuple[int, int],
    *,
    max_inst: int = 4000,
    gp_value: Optional[int] = None,
    phys_base: int = 0x1FC00000,
) -> Tuple[List[Ref], set]:
    """Abstract-interpret one function, returning (refs, reached_addrs).

    A reference is recorded whenever a register becomes a known constant inside
    ``window`` (lo, hi].  The walk is a worklist over the CFG; at joins where
    two paths disagree the register becomes UNKNOWN (no guess).
    """
    refs: List[Ref] = []
    reached: set = set()
    seen: set = set()
    # state[pc] = register map at entry to pc
    _seed = {} if gp_value is None else {GP: gp_value}
    state: Dict[int, Dict[int, object]] = {entry: dict(_seed)}
    work = [entry]
    steps = 0
    while work and steps < max_inst:
        pc = work.pop()
        if pc in seen or not sl.contains(pc) or (pc in entries and pc != entry):
            continue
        seen.add(pc)
        reached.add(pc)
        regs = dict(state.get(pc, {}))
        w = sl.word(pc)
        if w is None:
            continue
        steps += 1
        op = _op(w)

        def setting(rd_: int, val: object) -> None:
            regs[rd_] = UNKNOWN if val is None else val
            if isinstance(val, int) and not isinstance(val, bool) and window[0] <= val <= window[1]:
                refs.append(Ref(pc, rd_, val, entry))

        if op == 0x0F:                       # lui rt, imm
            setting(_rt(w), (_uimm(w) << 16) & 0xFFFFFFFFFFFFFFFF)
        elif op == 0x0D:                     # ori rt, rs, imm
            base = regs.get(_rs(w), UNKNOWN)
            setting(_rt(w), base | _uimm(w) if isinstance(base, int) and base < (1 << 16) else UNKNOWN)
        elif op in (0x09, 0x19, 0x24, 0x25):  # addiu/daddiu
            base = regs.get(_rs(w), UNKNOWN)
            setting(_rt(w), base + _simm(w) if isinstance(base, int) else UNKNOWN)
        elif op == 0 and _fn(w) == 0x38:     # dsll rd, rt, sa
            base = regs.get(_rt(w), UNKNOWN)
            setting(_rd(w), (base << _sa(w)) & 0xFFFFFFFFFFFFFFFF if isinstance(base, int) else UNKNOWN)
        elif op == 0 and _fn(w) == 0x2D:     # daddu rd, rs, rt
            a, b = regs.get(_rs(w), UNKNOWN), regs.get(_rt(w), UNKNOWN)
            setting(_rd(w), a + b if isinstance(a, int) and isinstance(b, int) else UNKNOWN)
        elif op == 0 and _fn(w) == 0x25:     # or rd, rs, rt
            a, b = regs.get(_rs(w), UNKNOWN), regs.get(_rt(w), UNKNOWN)
            setting(_rd(w), a | b if isinstance(a, int) and isinstance(b, int) else UNKNOWN)
        elif op in (0x37, 0x23, 0x1B, 0x27, 0x33):  # ld/lw/ldl/lwu/ldr
            # The PROM image IS its own memory: a load from a *known* address
            # yields a known value (this is what resolves a pointer loaded out
            # of a table).  Unknown base -> UNKNOWN (no guess).
            base = regs.get(_rs(w), UNKNOWN)
            val = UNKNOWN
            if isinstance(base, int):
                addr = base + _simm(w)
                n = 8 if op == 0x37 else 4
                # The image is a straight VA->file slice, but PROM data is also
                # reached by physical / mirrored (0xc0000000_xxxxxxxx) addresses;
                # normalize those to the slice too (phys_base + slot).
                if (addr >> 32) == 0xC0000000:
                    addr = addr & 0xFFFFFFFF
                if 0x1FC00000 <= addr < 0x1FC00000 + sl.va_end - sl.va_base:
                    off = sl.code_off + (addr - 0x1FC00000)
                else:
                    off = addr - sl.va_base
                if 0 <= off and off + n <= len(sl.code):
                    fmt = (">Q" if n == 8 else ">I") if sl.big_endian else ("<Q" if n == 8 else "<I")
                    val = struct.unpack_from(fmt, sl.code, off)[0]
            setting(_rt(w), val)
        elif op in (0x02, 0x03):             # j/jal: caller-saved clobbered
            for r in CALLER_SAVED:
                regs[r] = UNKNOWN
        elif op == 0 and _fn(w) == 0x09:     # jalr: clobber caller-saved
            for r in CALLER_SAVED:
                regs[r] = UNKNOWN
        else:
            # Any other writer we don't model -> clobber its destination.
            if op == 0 and _fn(w) in (0x20, 0x21, 0x24, 0x26, 0x27, 0x02, 0x03, 0x2A, 0x2B, 0x00):
                setting(_rd(w), UNKNOWN)

        for succ in _entry_successors(w, pc):
            if succ in seen:
                continue
            prev = state.get(succ)
            if prev is None:
                state[succ] = dict(regs)
            else:
                merged = {r: _join(prev.get(r, UNKNOWN), regs.get(r, UNKNOWN))
                          for r in set(prev) | set(regs)}
                state[succ] = merged
            work.append(succ)
    return refs, reached


# --------------------------------------------------------------------------- #
# Entry discovery + function spans
# --------------------------------------------------------------------------- #
def find_entries(sl: Slice, *, vector_len: int = 32) -> List[int]:
    """Bootstrap entries: the reset jump-vector table + every jal/jalr target."""
    entries: set = set()
    # The reset vector is a table of `j target` (opcode 2) separated by nops.
    pc = sl.va_base
    for _ in range(vector_len):
        w = sl.word(pc)
        if w is None:
            break
        if _op(w) == 0x02:
            entries.add(_jtarget(w, pc))
        pc += 8
    # Every direct jal target is an entry too.
    pc = sl.va_base
    end = sl.va_end
    while pc + 4 <= end:
        w = sl.word(pc)
        if w is not None and _op(w) == 0x03:
            entries.add(_jtarget(w, pc))
        pc += 4
    entries.add(sl.va_base)
    # Keep only targets that actually land in the slice (the jal scan also sees
    # data words, which can form constants outside the code range).
    return sorted(e for e in entries if sl.contains(e))


def function_spans(entries: Sequence[int], sl: Slice) -> List[Tuple[int, int]]:
    """Half-open [entry, next_entry) spans, clipped to the slice."""
    es = sorted(set(entries))
    out = []
    for i, e in enumerate(es):
        nxt = es[i + 1] if i + 1 < len(es) else sl.va_end
        out.append((e, min(nxt, sl.va_end)))
    return out


def enclosing_function(addr: int, spans: Sequence[Tuple[int, int]]) -> Optional[int]:
    for lo, hi in spans:
        if lo <= addr < hi:
            return lo
    return None


# --------------------------------------------------------------------------- #
# Anchor resolution
# --------------------------------------------------------------------------- #
@dataclass
class Resolution:
    literal: str
    src: str
    anchor_va: int
    function: Optional[int]
    site: Optional[int]


@dataclass
class DefuseReport:
    resolved: List[Resolution] = field(default_factory=list)
    unresolved: List[Tuple[str, int]] = field(default_factory=list)
    entries: int = 0
    functions_with_refs: int = 0

    @property
    def coverage(self) -> float:
        total = len(self.resolved) + len(self.unresolved)
        return len(self.resolved) / total if total else 0.0


def resolve_anchors(
    sl: Slice,
    anchors: Dict[str, dict],
    *,
    window: Optional[Tuple[int, int]] = None,
) -> DefuseReport:
    """Map each anchor's VA to the enclosing function via data-flow.

    ``anchors`` maps literal -> {"off": file_off, "src": "file:line"} exactly as
    in ip27-string-anchor.json, where VA = va_base + (off - code_off).
    """
    # anchor VA -> literal
    va_to_lit: Dict[int, Tuple[str, str]] = {}
    for lit, meta in anchors.items():
        va = sl.va_base + (meta["off"] - sl.code_off)
        va_to_lit[va] = (lit, meta.get("src", "?"))

    if window is None:
        vals = sorted(va_to_lit)
        window = (vals[0], vals[-1])

    entries = find_entries(sl)
    report = DefuseReport(entries=len(entries))

    # One pass per entry; a reference's *value* is the anchor VA it points at.
    hits: Dict[int, int] = {}
    funcs_ref: set = set()
    ents = frozenset(entries)
    for entry in entries:
        refs, _ = propagate_function(sl, entry, ents, window)
        for r in refs:
            if r.value in va_to_lit and va_to_lit[r.value][0] is not None:
                hits.setdefault(r.value, r.function)
                funcs_ref.add(r.function)
    report.functions_with_refs = len(funcs_ref)

    for va, (lit, src) in va_to_lit.items():
        if lit is None:
            continue
        fn = hits.get(va)
        if fn is None:
            report.unresolved.append((lit, va))
        else:
            report.resolved.append(Resolution(lit, src, va, fn, None))
    return report
