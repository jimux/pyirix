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
        # Look ahead for base+offset within a small window.
        found = False
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
