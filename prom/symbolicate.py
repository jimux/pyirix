"""PROM function-level symbolication: anchor -> enclosing-function mapping.

The parked step from the IP27 symbolication work (note 50 §6): the PROM does not
reference its data with kseg immediates, and a bounded base+immediate scan found
no refs landing in the string blob.  This module does the next bounded thing:
**intra-function register propagation** of the 64-bit VA base, so a loaded
address (base + offset) can be tied back to a source string anchor and to the
function that references it.

Discipline: every resolved name is a *measured* base+offset; anything the
propagation cannot carry is left unresolved (``None``), never guessed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .vaform import PromProfile, decode_addr_chain, _op, _rs, _rt, _rd, _sa, _fn, _imm

#: Instructions that write their rd/rt with a value we can track (address forms).
_LUI, _DADDIU, _ADDIU, _ORI, _DADDU, _ADDU, _DSLL, _DSLL32 = 0x0F, 0x19, 0x09, 0x0D, 0x00, 0x00, 0x00, 0x00
_JAL, _BEQ, _BNE, _JR, _LD = 0x03, 0x04, 0x05, 0x00, 0x37


@dataclass
class AnchorRef:
    """A resolved reference from a PROM instruction to a source string anchor."""

    va: int                # instruction VA
    function_va: int       # enclosing function entry VA
    base_value: int        # the folded VA base
    offset: int            # base-relative offset added at the load
    anchor_off: int        # file offset of the anchor in the image
    anchor_text: str       # the source literal


@dataclass
class SymbolicationResult:
    refs: List[AnchorRef] = field(default_factory=list)
    unresolved_bases: int = 0     # VA chains whose base we could not carry
    scanned: int = 0              # instruction sites examined


def _word(profile: PromProfile, image: bytes, va: int) -> Optional[int]:
    return profile.word(image, va)


def _fold_chain_at(profile: PromProfile, image: bytes, va: int) -> Optional[tuple]:
    """Fold a VA-forming chain starting at ``va``; return (reg, value) or None."""
    n = _word(profile, image, va)
    if n is None or _op(n) != _LUI:
        return None
    words = [n]
    cur = va + 4
    for _ in range(8):
        w = _word(profile, image, cur)
        if w is None:
            break
        words.append(w)
        cur += 4
        if _op(w) == _LUI:
            break
    val = decode_addr_chain(words)
    if val is None:
        return None
    return (_rt(n), val)


def _load_offset(profile: PromProfile, image: bytes, va: int, base_reg: int) -> Optional[int]:
    """If the instruction at ``va`` loads ``base_reg + imm`` (daddiu/ld), return imm."""
    w = _word(profile, image, va)
    if w is None:
        return None
    op = _op(w)
    if op in (_DADDIU, _ADDIU) and _rs(w) == base_reg:
        return _imm(w)
    if op == _LD and _rs(w) == base_reg:
        return _imm(w)
    return None


def symbolicate(
    image: bytes,
    profile: PromProfile,
    anchors: Dict[int, str],
    *,
    max_sites: int = 200000,
) -> SymbolicationResult:
    """Map PROM address-forming sites to source string anchors.

    ``anchors`` maps a **file offset** to its source literal (the
    ``ip27-string-anchor.json`` shape).  Scans the code slice for ``lui`` chains,
    folds each to its 64-bit constant, then in the following few instructions
    looks for a ``base + offset`` add/load whose target lands on an anchor.

    Bounded: a chain whose base we cannot fold, or an add/load we cannot tie to
    the base register, is counted unresolved and skipped -- never guessed.
    """
    res = SymbolicationResult()
    lo = profile.va_base
    hi = profile.va_base + profile.code_size
    va = lo
    sites = 0
    while va < hi:
        sites += 1
        res.scanned += 1
        if sites > max_sites:
            break
        folded = _fold_chain_at(profile, image, va)
        if folded is None:
            va += 4
            continue
        reg, base = folded
        # The folded constant may itself BE the string VA (the PROM builds
        # per-string VAs inline) -- check it directly, then look ahead for
        # base+offset within a small window.
        found = _maybe_ref(res, profile, profile.code_off, base, va, anchors)
        for step in range(1, 6):
            off = _load_offset(profile, image, va + step * 4, reg)
            if off is None:
                continue
            target = (base + off) & 0xFFFFFFFFFFFFFFFF
            # Reduce XKPHYS 0xc0000000_... to the physical/kseg1 offset window.
            # The PROM physical base is va_base & 0x1fffffff (0x1fc00000 for
            # IP27); file_off = code_off + (phys - phys_base).
            phys = target & 0x1FFFFFFF
            phys_base = profile.va_base & 0x1FFFFFFF
            fo = profile.code_off + (phys - phys_base)
            if fo in anchors:
                res.refs.append(AnchorRef(
                    va=va, function_va=0, base_value=base, offset=off,
                    anchor_off=fo, anchor_text=anchors[fo],
                ))
                found = True
                break
        if not found:
            res.unresolved_bases += 1
        va += 4
    return res


# --- def-use-across-calls pass --------------------------------------------

#: Callee-saved GPRs (o32/n32/n64 share this set for s0-s7 + fp/sp/gp/ra).
_CALLEE_SAVED = {16, 17, 18, 19, 20, 21, 22, 23, 28, 29, 30, 31}
_ADDIU_LIKE = {0x19, 0x09}          # daddiu, addiu  (rt = rs + imm)
_DADDU_LIKE = {0x00}                # addu/daddu handled by funct below


def _fun(w: int) -> int:
    return _fn(w)


def _is_daddu(w: int) -> bool:
    return _op(w) == 0 and _fn(w) in (0x21, 0x2D) and _rd(w) == _rt(w) != 0


def symbolicate_defuse(
    image: bytes,
    profile: PromProfile,
    anchors: Dict[int, str],
    *,
    max_insns: int = 400000,
) -> SymbolicationResult:
    """Def-use-across-calls symbolication.

    Walks the code slice linearly, maintaining a register->VA map that
    **survives calls for callee-saved registers** (so a base loaded once and
    used later, across a `jal`, still resolves).  A load/store/move whose
    computed address or value lands on a string anchor is recorded; anything
    not carried by the map is left unresolved.
    """
    res = SymbolicationResult()
    va = profile.va_base
    hi = profile.va_base + profile.code_size
    regval: Dict[int, int] = {}
    off_of = profile.code_off
    while va < hi and res.scanned < max_insns:
        res.scanned += 1
        w = profile.word(image, va)
        if w is None:
            break
        op = _op(w)
        folded = _fold_chain_at(profile, image, va)
        if folded is not None:
            regval[folded[0]] = folded[1]
            _maybe_ref(res, profile, off_of, folded[1], va, anchors)
            va += 4
            continue
        if op in _ADDIU_LIKE and _rs(w) in regval:
            v = (regval[_rs(w)] + _imm(w)) & 0xFFFFFFFFFFFFFFFF
            regval[_rt(w)] = v
            _maybe_ref(res, profile, off_of, v, va, anchors)
        elif op == 0x0D and _rs(w) in regval:        # ori rt, rs, imm
            v = regval[_rs(w)] | (w & 0xFFFF)
            regval[_rt(w)] = v
            _maybe_ref(res, profile, off_of, v, va, anchors)
        elif op == 0x0C and _rs(w) in regval:        # andi rt, rs, imm
            v = regval[_rs(w)] & (w & 0xFFFF)
            regval[_rt(w)] = v
        elif op == 0 and _fn(w) in (0x38, 0x3C) and _rt(w) in regval:
            # dsll/dsll32 rd, rt, sa
            sa = _sa(w)
            if _fn(w) == 0x3C:
                sa += 32
            v = (regval[_rt(w)] << sa) & 0xFFFFFFFFFFFFFFFF
            regval[_rd(w)] = v
            _maybe_ref(res, profile, off_of, v, va, anchors)
        elif op == 0 and _fn(w) in (0x00, 0x02, 0x03) and _rt(w) in regval:
            # sll/srl/sra rd, rt, sa (32-bit windows used to build an index)
            v = (regval[_rt(w)] >> _sa(w) if _fn(w) == 0x02 else regval[_rt(w)] << _sa(w)) & 0xFFFFFFFFFFFFFFFF
            regval[_rd(w)] = v
        elif op == 0 and _fn(w) in (0x22, 0x23, 0x2E, 0x2F) and _rs(w) in regval and _rt(w) in regval:
            # sub/subu/dsub/dsubu rd, rs, rt
            v = (regval[_rs(w)] - regval[_rt(w)]) & 0xFFFFFFFFFFFFFFFF
            regval[_rd(w)] = v
            _maybe_ref(res, profile, off_of, v, va, anchors)
        elif op in (0x23, 0x24, 0x20, 0x21, 0x25, 0x27) and _rs(w) in regval:
            # lw/lwu/lb/lbu/lh/lhu rt, imm(rs): track the loaded word (zero/sign-extended)
            lfo = profile.code_off + (((regval[_rs(w)] + _imm(w)) & 0x1FFFFFFF) - (profile.va_base & 0x1FFFFFFF))
            if 0 <= lfo <= len(image) - 4:
                raw = int.from_bytes(image[lfo:lfo + 4], "big")
                if op == 0x24:   raw &= 0xFF
                elif op == 0x25: raw &= 0xFFFF
                regval[_rt(w)] = raw & 0xFFFFFFFFFFFFFFFF
        elif _is_daddu(w) and _rs(w) in regval and _rt(w) in (0, 0):
            pass
        elif op == 0 and _fn(w) in (0x20, 0x21, 0x2C, 0x2D):
            # add/addu/dadd/daddu rd, rs, rt  -- the PROM forms VAs this way too
            rs, rt, rd = _rs(w), _rt(w), _rd(w)
            if rd == 0:
                pass
            elif rs in regval and rt in regval:
                regval[rd] = (regval[rs] + regval[rt]) & 0xFFFFFFFFFFFFFFFF
                _maybe_ref(res, profile, off_of, regval[rd], va, anchors)
            elif rs in regval and rt == 0:
                regval[rd] = regval[rs]
            elif rt in regval and rs == 0:
                regval[rd] = regval[rt]
        elif op in (0x37, 0x27, 0x3F, 0x2B, 0x23):   # ld/sd/... base+imm
            if _rs(w) in regval:
                v = (regval[_rs(w)] + _imm(w)) & 0xFFFFFFFFFFFFFFFF
                _maybe_ref(res, profile, off_of, v, va, anchors)
                if op == 0x37:                        # ld rt, imm(rs): track the loaded u64
                    lfo = profile.code_off + ((v & 0x1FFFFFFF) - (profile.va_base & 0x1FFFFFFF))
                    if 0 <= lfo <= len(image) - 8:
                        regval[_rt(w)] = int.from_bytes(image[lfo:lfo + 8], "big")
        elif op == 0x03:                              # jal
            for r in list(regval):
                if r not in _CALLEE_SAVED:
                    del regval[r]
        elif op in (0x04, 0x05, 0x02, 0x01, 0x06, 0x07, 0x14, 0x15):
            pass                                      # branches: keep the map
        elif op in (0x00,) and _fn(w) in (0x08, 0x09):  # jr/jalr
            if _fn(w) == 0x08 and _rs(w) == 31:
                regval.clear()                        # return: new function
            for r in list(regval):
                if r not in _CALLEE_SAVED:
                    del regval[r]
        va += 4
    return res


def _maybe_ref(res, profile, off_of, value, va, anchors) -> bool:
    phys = value & 0x1FFFFFFF
    phys_base = profile.va_base & 0x1FFFFFFF
    fo = off_of + (phys - phys_base)
    if fo in anchors:
        res.refs.append(AnchorRef(va=va, function_va=0, base_value=value, offset=0,
                                  anchor_off=fo, anchor_text=anchors[fo]))
        return True
    return False


#: The IP27 region-descriptor table (VA 0xbfc5b024): {u32 phys, u32 0xc0000000} pairs.
IP27_DESCRIPTOR_VA = 0xBFC5B024
DESCRIPTOR_CONST = 0xC0000000


def descriptor_table(image: bytes, profile: PromProfile, *,
                     va: int = IP27_DESCRIPTOR_VA, max_entries: int = 64) -> List[int]:
    """Parse the IP27 region-descriptor table into its region-base VAs.

    Each 8-byte entry is ``{u32 phys, u32 0xc0000000}`` (big-endian); the region
    base VA is ``0xc0000000 << 32 | phys``.  Stops at the first entry whose
    constant half is not ``0xc0000000`` (so a non-table region ends it cleanly).
    """
    out: List[int] = []
    fo = profile.file_off_of(va)
    for i in range(max_entries):
        off = fo + i * 8
        if off < 0 or off + 8 > len(image):
            break
        phys = struct.unpack_from(">I", image, off)[0]
        const = struct.unpack_from(">I", image, off + 4)[0]
        if const != DESCRIPTOR_CONST:
            break
        out.append((DESCRIPTOR_CONST << 32) | phys)
    return out


# ---------------------------------------------------------------------------
# CFG/dataflow symbolication
# ---------------------------------------------------------------------------

#: Registers preserved across a call (the O32/N32 callee-saved convention).
#: $ra (31) is deliberately EXCLUDED here -- it does not carry a data value
#: across a call.  The linear pass's own `_CALLEE_SAVED` (which includes it) is
#: left untouched so its measured result does not move.
_CALLEE_SAVED_CFG = frozenset(range(16, 24)) | {28, 29, 30}

#: The O32/N32 argument registers ($a0-$a3): a value in one of these at a `jal`
#: IS the callee's incoming argument, so seeding a function with them carries a
#: base that is *passed* to it rather than built inside it.
_ARG_REGS = frozenset(range(4, 8))


def _branch_target(va: int, w: int) -> Optional[int]:
    """Absolute target of a branch/jump word, or None."""
    op = _op(w)
    if op in (0x04, 0x05, 0x06, 0x07, 0x01, 0x14, 0x15, 0x16, 0x17):  # b/beq/bne/blez/bgtz
        return (va + 4 + (_imm(w) << 2)) & 0xFFFFFFFFFFFFFFFF
    if op in (0x02, 0x03):  # j/jal: PC top bits | (index << 2)
        idx = w & 0x03FFFFFF
        return ((va + 4) & ~0x0FFFFFFF) | (idx << 2)
    if op == 0 and _fn(w) in (0x08, 0x09):  # jr/jalr: target is dynamic
        return None
    return None


def _transfer(regval: Dict[int, int], profile, image, off_of, va, anchors,
              seen: set) -> Dict[int, int]:
    """Apply one instruction to the register map; record any anchor ref once."""
    nv = dict(regval)
    w = profile.word(image, va)
    if w is None:
        return nv
    op = _op(w)

    def _ref(v):
        phys = v & 0x1FFFFFFF
        fo = off_of + (phys - (profile.va_base & 0x1FFFFFFF))
        if fo in anchors and (va, fo) not in seen:
            seen.add((va, fo))
            _REF_ACC.append(AnchorRef(va=va, function_va=0, base_value=v,
                                      offset=0, anchor_off=fo,
                                      anchor_text=anchors[fo]))

    folded = _fold_chain_at(profile, image, va)
    if folded is not None:
        nv[folded[0]] = folded[1]
        _ref(folded[1])
        return nv
    if op in _ADDIU_LIKE and _rs(w) in nv:
        v = (nv[_rs(w)] + _imm(w)) & 0xFFFFFFFFFFFFFFFF
        nv[_rt(w)] = v
        _ref(v)
    elif op == 0x0D and _rs(w) in nv:
        v = nv[_rs(w)] | (w & 0xFFFF)
        nv[_rt(w)] = v
        _ref(v)
    elif op == 0 and _fn(w) in (0x38, 0x3C) and _rt(w) in nv:
        sa = _sa(w) + (32 if _fn(w) == 0x3C else 0)
        v = (nv[_rt(w)] << sa) & 0xFFFFFFFFFFFFFFFF
        nv[_rd(w)] = v
        _ref(v)
    elif op == 0 and _fn(w) in (0x20, 0x21, 0x2C, 0x2D):
        rs, rt, rd = _rs(w), _rt(w), _rd(w)
        if rd and rs in nv and rt in nv:
            nv[rd] = (nv[rs] + nv[rt]) & 0xFFFFFFFFFFFFFFFF
            _ref(nv[rd])
        elif rd and rt == 0 and rs in nv:
            nv[rd] = nv[rs]
        elif rd and rs == 0 and rt in nv:
            nv[rd] = nv[rt]
    elif op in (0x23, 0x24, 0x20, 0x21, 0x25, 0x27, 0x37) and _rs(w) in nv:
        v = (nv[_rs(w)] + _imm(w)) & 0xFFFFFFFFFFFFFFFF
        _ref(v)
        if op in (0x37, 0x23):
            lfo = off_of + ((v & 0x1FFFFFFF) - (profile.va_base & 0x1FFFFFFF))
            n = 8 if op == 0x37 else 4
            if 0 <= lfo <= len(image) - n:
                nv[_rt(w)] = int.from_bytes(image[lfo:lfo + n], "big")
    elif op == 0x0F:  # lui: the low 16 bits are zero
        nv[_rt(w)] = (w & 0xFFFF) << 16
    elif op == 0x03:  # jal
        for r in list(nv):
            if r not in _CALLEE_SAVED_CFG:
                del nv[r]
    elif op == 0 and _fn(w) in (0x08, 0x09):
        for r in list(nv):
            if r not in _CALLEE_SAVED_CFG:
                del nv[r]
    return nv


def symbolicate_cfg(
    image: bytes,
    profile: PromProfile,
    anchors: Dict[int, str],
    *,
    max_blocks: int = 60000,
    max_passes: int = 12,
) -> SymbolicationResult:
    """CFG/dataflow symbolication.

    Splits the slice at branch targets and after control transfers, then runs a
    work-list over the basic blocks, merging the register->VA map at a join by
    **keeping only entries that agree on every incoming edge** (a value that
    differs is dropped -- never guessed).  This carries a base through a branch
    or a back edge that the linear pass loses at the first taken branch.
    """
    global _REF_ACC
    res = SymbolicationResult()
    vabase = profile.va_base
    hi = vabase + profile.code_size
    words: Dict[int, int] = {}
    va = vabase
    while va < hi:
        w = profile.word(image, va)
        if w is None:
            break
        words[va] = w
        va += 4
    if not words:
        return res
    lo, top = min(words), max(words)

    # Leaders: the entry, every branch target, and the word after a transfer.
    leaders = {lo}
    for va2, w in words.items():
        t = _branch_target(va2, w)
        if t is not None and lo <= t <= top:
            leaders.add(t)
        op = _op(w)
        if op in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x01, 0x14, 0x15, 0x16, 0x17) or (
                op == 0 and _fn(w) in (0x08, 0x09)):
            if va2 + 4 in words:
                leaders.add(va2 + 4)
    order = sorted(leaders)
    block_of = {}
    for i, st in enumerate(order):
        end = order[i + 1] if i + 1 < len(order) else top + 4
        assert end > st
        for a in range(st, end, 4):
            if a in words:
                block_of[a] = st
    blocks = {}
    for st in order:
        ins = [a for a in range(st, (order[order.index(st) + 1]
                                      if order.index(st) + 1 < len(order)
                                      else top + 4), 4) if a in words]
        if ins:
            blocks[st] = ins

    entry = {}          # block start -> merged regval at block entry
    seen: set = set()
    _REF_ACC = res.refs
    merges = 0
    # Seed: the image entry AND every `jal` target.  A function reached by call
    # does not start empty -- the caller's CALLEE-SAVED registers hold live bases
    # across the call.  Take that context from a linear walk (the def-use pass's
    # model) keyed by call site, so the CFG starts each function with the values
    # the linear pass would have carried into it.  Conflicting contexts at the
    # same target keep only the agreeing entries.
    ctx: Dict[int, Dict[int, int]] = {}
    lreg: Dict[int, int] = {}
    lva = lo
    while lva <= top:
        lw = words.get(lva)
        if lw is None:
            lva += 4
            continue
        if _op(lw) == 0x03:
            t = _branch_target(lva, lw)
            if t is not None and t in blocks:
                saved = {r: v for r, v in lreg.items()
                         if r in _CALLEE_SAVED_CFG or r in _ARG_REGS}
                if t in ctx:
                    cur = ctx[t]
                    ctx[t] = {r: v for r, v in cur.items()
                              if r in saved and saved[r] == v}
                else:
                    ctx[t] = saved
            for r in list(lreg):
                if r not in _CALLEE_SAVED_CFG:
                    del lreg[r]
        else:
            lreg = _transfer(lreg, profile, image, profile.code_off, lva,
                             anchors, set())
        lva += 4
    seeds = {lo}
    for ava, aw in words.items():
        if _op(aw) == 0x03:
            t = _branch_target(ava, aw)
            if t is not None and t in blocks:
                seeds.add(t)
    for st in seeds:
        entry[st] = dict(ctx.get(st, {}))
    for _ in range(max_passes):
        changed = False
        for st in order:
            ins = blocks.get(st)
            if not ins:
                continue
            if st in entry:
                regval = dict(entry[st])
            else:
                regval = dict(entry.get(st, {}))
                if st not in entry:
                    continue
            for a in ins:
                regval = _transfer(regval, profile, image, profile.code_off,
                                   a, anchors, seen)
            last = ins[-1]
            lw = words[last]
            succ = []
            if _op(lw) in (0x02, 0x03):
                succ = []
            elif _op(lw) in (0x04, 0x05, 0x06, 0x07, 0x01, 0x14, 0x15, 0x16, 0x17):
                for cand in (_branch_target(last, lw), last + 4):
                    if cand is not None and cand in blocks:
                        succ.append(cand)
            elif _op(lw) == 0 and _fn(lw) in (0x08, 0x09):
                succ = []
            else:
                if last + 4 in blocks:
                    succ.append(last + 4)
            for s in succ:
                if s not in entry:
                    entry[s] = dict(regval)
                    changed = True
                    merges += 1
                else:
                    cur = entry[s]
                    new = {r: v for r, v in cur.items()
                           if r in regval and regval[r] == v}
                    if len(new) != len(cur):
                        entry[s] = new
                        changed = True
                        merges += 1
        if not changed:
            break
    res.scanned = len(words)
    res.unresolved_bases = merges
    return res


_REF_ACC: List[AnchorRef] = []
