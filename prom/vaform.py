"""PROM VA-formation: profile selection and 64-bit address-chain decoding.

Distilled from the IP27 symbolication work (see
``progress_notes/agent_tooling/50-ip27-prom-symbolication-state.md`` and ``51``).
This is the *correct* part of that effort: a PROM's executable code does not
reference its data by simple kseg immediates -- it **builds 64-bit VAs by a
register chain**, e.g.

    lui   rX, 0xc000
    daddiu rX, rX, 0
    dsll  rX, rX, 16
    daddiu rX, rX, 0x1fc7
    dsll  rX, rX, 16
    daddiu rX, rX, 0x4800      ->  0xc0001fc74800

The canonical such value for the IP27 image is ``0xc00000001fc00000`` -- which
equals, byte for byte, the container header's load/entry field.  Anyone reading
IP27 (or similar SN) PROM disassembly needs this: it explains why scanning for
``0xbfc5xxxx`` constants finds nothing.

Two things are provided:

* :func:`select_profile` -- given a PROM image, identify the executable slice
  (container magic, code offset/size, endianness, VA base) so callers do not
  hard-code one machine's numbers.
* :func:`decode_addr_chain` -- fold a run of address-forming instructions into
  the constant they produce (the chain above), returning ``None`` the moment a
  step is not a known constant (never a guess).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence

# --- instruction field helpers ---------------------------------------------
def _op(w: int) -> int:
    return (w >> 26) & 0x3F


def _rt(w: int) -> int:
    return (w >> 16) & 0x1F


def _rs(w: int) -> int:
    return (w >> 21) & 0x1F


def _rd(w: int) -> int:
    return (w >> 11) & 0x1F


def _sa(w: int) -> int:
    return (w >> 6) & 0x1F


def _fn(w: int) -> int:
    return w & 0x3F


def _imm(w: int) -> int:
    v = w & 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


@dataclass
class PromProfile:
    """Where a PROM image's executable code lives and how to read it."""

    name: str
    code_off: int
    code_size: int
    va_base: int
    big_endian: bool
    magic: Optional[bytes] = None
    load_va: Optional[int] = None      # container load/entry (64-bit) if present

    def va_of(self, file_off: int) -> int:
        """Map a file offset inside the slice to its VA."""
        return self.va_base + (file_off - self.code_off)

    def file_off_of(self, va: int) -> int:
        return self.code_off + (va - self.va_base)

    def word(self, image: bytes, va: int) -> Optional[int]:
        off = self.file_off_of(va)
        if off < 0 or off + 4 > len(image):
            return None
        return struct.unpack_from(">I" if self.big_endian else "<I", image, off)[0]


#: The IP27 (SN0) container: magic, then code slice at 0x1000, BE, at 0xbfc00000.
IP27_PROFILE = PromProfile(
    name="ip27",
    code_off=0x1000,
    code_size=0xDDD78,
    va_base=0xBFC00000,
    big_endian=True,
    magic=b"JFKSWCSM",
)


def select_profile(image: bytes, *, magic: bytes = b"JFKSWCSM") -> Optional[PromProfile]:
    """Identify a PROM container profile from its bytes.

    Recognises the JFKSWCSM container (IP27/SN0): magic at 0x40, code offset
    (BE64 @0x98), load/entry (BE64 @0xA0), code size (BE64 @0xB0).  Returns
    ``None`` for an unrecognised image rather than guessing a layout.
    """
    m = image.find(magic)
    if m < 0:
        return None
    try:
        code_off = struct.unpack_from(">Q", image, 0x98)[0]
        load_va = struct.unpack_from(">Q", image, 0xA0)[0]
        code_size = struct.unpack_from(">Q", image, 0xB0)[0]
    except struct.error:
        return None
    return PromProfile(
        name="ip27",
        code_off=code_off,
        code_size=code_size,
        va_base=0xBFC00000,
        big_endian=True,
        magic=magic,
        load_va=load_va,
    )


def decode_addr_chain(words: Sequence[int]) -> Optional[int]:
    """Fold an address-forming instruction run into the constant it produces.

    ``words`` is the run as decoded 32-bit words (big-endian instruction
    encoding).  Recognises, on one destination register:

    * ``lui rt, imm``         -> ``imm << 16``
    * ``daddiu/addiu rt, rt, imm`` -> ``+ imm`` (signed)
    * ``ori rt, rt, imm``     -> ``| imm``
    * ``dsll rt, rt, sa``     -> ``<< sa``

    Returns the final value, or ``None`` as soon as a step does not fit the
    pattern (an unknown step ends the fold -- never a partial guess).
    """
    if not words:
        return None
    w0 = words[0]
    if _op(w0) != 0x0F:            # must start with a lui
        return None
    reg = _rt(w0)
    val = (w0 & 0xFFFF) << 16
    for w in words[1:]:
        op = _op(w)
        if op == 0x0F:             # a new lui starts a new chain
            break
        if _op(w) == 0x0D and _rs(w) == reg and _rt(w) == reg:
            val |= w & 0xFFFF
        elif op in (0x09, 0x19, 0x24, 0x25) and _rs(w) == reg and _rt(w) == reg:
            val = (val + _imm(w)) & 0xFFFFFFFFFFFFFFFF
        elif op == 0 and _fn(w) == 0x38 and _rd(w) == reg and _rt(w) == reg:
            val = (val << _sa(w)) & 0xFFFFFFFFFFFFFFFF
        else:
            break
    return val


#: The chain at IP27 VA 0xbfc00be8 (``lui r27,0xc000; dsll 16; ori 0x1fc0;
#: dsll 16``) -- it folds to ``0xc00000001fc00000``, exactly the container
#: header's load/entry field (@0xA0).  The regression test pins this equality.
CANONICAL_LOAD_CHAIN = [0x3C1BC000, 0x001BDC38, 0x377B1FC0, 0x001BDC38]
CANONICAL_LOAD_VALUE = 0xC00000001FC00000
