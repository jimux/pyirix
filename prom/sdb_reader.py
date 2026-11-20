"""Read the SDB record layout out of the program that wrote the `sdb ` files.

The 32 ``vfc-database`` containers in PROM_library are written by SGI's SDB
library, and the corpus holds the reader built on it: ``bins/graphics/venice/
irsaudit`` (O32, MIPS-II) and ``irsaudit_84013ec6`` (N32, MIPS-III). Both are
stripped but keep their dynamic symbols, so the layout those files rest on can be
read out of the producer's own code instead of measured on the files alone:

  * :func:`read` parses one build and returns an :class:`SdbSchema` carrying
    - the wire order of ``xdr_SDBsymbolTableEntry``'s four fields (name, type,
      element index, file offset) as codec names resolved from the .got,
    - the two field offsets ``SDBgetSymbolDatatype`` and
      ``SDBgetSymbolElementCount`` return out of a resolved entry,
    - the symbol-name bound ``xdr_SDBsymbolName`` enforces,
    - the wire layout of ``xdr_SDBfileHeader``, walked from the codecs it calls,
    - the ``mapTypeToXDRPROC`` table's type code -> (codec, element width).

Nothing here re-implements a disassembler: instructions are decoded one at a
time (opcode, rs/rt/rd, immediate), and every step is either a hard fact of the
ELF (sections, dynamic tags, dynamic symbols) or a single instruction pattern
with a stated meaning. A build whose code no longer has the shape is refused
loudly (:class:`SdbLayoutError`) rather than guessed at.

    from pyirix.prom import sdb_reader
    schema = sdb_reader.read("bins/graphics/venice/irsaudit")
    schema.entry_wire          # (('xdr_SDBsymbolName', 0), ('xdr_SDBdataType', 4), ...)
    schema.datatype_offset     # 4
    schema.element_count_offset  # 8
    schema.name_bound          # 31
    schema.header_wire         # (('xdr_bytes', 0, 8), ('xdr_SDBversionNumber', 8, 8), ...)

The .got resolution is the MIPS rule: slot ``k`` (>= ``DT_MIPS_LOCAL_GOTNO``)
holds the address of dynamic symbol ``k - LOCAL_GOTNO + DT_MIPS_GOTSYM``. Slots
below that are local and hold an address, not a symbol index, so they are
reported as ``None`` rather than named by a coincidental value match.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from elftools.elf.elffile import ELFFile

__all__ = [
    "SdbLayoutError",
    "SdbSchema",
    "read",
    "read_bytes",
    "corpus_field_layout",
]

#: The record's four fields, in the order ``xdr_SDBsymbolTableEntry`` writes them.
ENTRY_FIELDS = ("xdr_SDBsymbolName", "xdr_SDBdataType",
                "xdr_SDBelementIndex", "xdr_SDBfileOffset")

#: XDR wire size of the fixed-size codecs, in bytes. Every XDR item is a
#: multiple of 4; a u_short and a bool both travel as one 4-byte unit.
XDR_UNIT = 4

#: The functions whose shape is read, and what each establishes.
ACCESSORS = {"SDBgetSymbolDatatype": "type", "SDBgetSymbolElementCount": "count"}

_SP_REGS = (29, 30, 31)   # sp, fp, ra: a base of these is a saved value, not the entry


class SdbLayoutError(ValueError):
    """The binary does not have the shape the SDB reader is read from."""


@dataclass(frozen=True)
class HeaderField:
    """One member of ``xdr_SDBfileHeader``'s wire layout."""

    codec: str          # dynamic-symbol name of the xdr_ proc called
    wire_offset: int    # byte offset in the file
    width: int          # bytes it occupies on the wire
    member_offset: Optional[int]   # offset of the struct member in memory
    maxsize: Optional[int] = None  # the declared bound, for xdr_bytes/xdr_array


@dataclass(frozen=True)
class SdbSchema:
    """What one build of the producer's SDB reader says the record layout is."""

    path: str
    abi: str                                # "o32" or "n32"
    gp: int                                 # the _gp the SDB functions run with
    entry_wire: Tuple[Tuple[str, int], ...]  # (codec, wire offset) in call order
    entry_members: Tuple[Optional[int], ...]  # struct member offset per call
    datatype_offset: int                    # field offset the type accessor reads
    element_count_offset: int               # ... and the element count accessor
    name_bound: int                         # xdr_SDBsymbolName's li a2,N
    header_wire: Tuple[HeaderField, ...] = field(default_factory=tuple)
    type_codecs: Dict[int, str] = field(default_factory=dict)
    type_widths: Dict[int, int] = field(default_factory=dict)

    @property
    def entry_codecs(self) -> Tuple[str, ...]:
        return tuple(name for name, _off in self.entry_wire)

    @property
    def header_codecs(self) -> Tuple[str, ...]:
        return tuple(f.codec for f in self.header_wire)

    def header_offset(self, codec: str, nth: int = 0) -> int:
        """Wire offset of the *nth* field encoded by *codec*, or -1."""
        seen = -1
        for f in self.header_wire:
            if f.codec == codec:
                seen += 1
                if seen == nth:
                    return f.wire_offset
        return -1


# --------------------------------------------------------------------- ELF ---

class _Image:
    """One ELF image: its loadable bytes, sections, dynamic symbols and tags."""

    def __init__(self, name: str, data: bytes):
        import io

        self.name = name
        try:
            self._load(io.BytesIO(data))
        except SdbLayoutError:
            raise
        except Exception as exc:        # a truncated or otherwise broken image
            raise SdbLayoutError("%s is not a readable MIPS ELF: %s" % (name, exc))

    def _load(self, stream) -> None:
        try:
            self.elf = ELFFile(stream)
        except Exception as exc:                    # a truncated or non-ELF image
            raise SdbLayoutError("%s is not a readable ELF: %s" % (self.name, exc))
        data = stream.getvalue()
        if self.elf.elfclass != 32 or self.elf.little_endian:
            raise SdbLayoutError("%s is not a 32-bit big-endian MIPS ELF"
                                 % self.name)
        self.data = data
        self._segments = []
        for ph in self.elf.iter_segments():
            if ph["p_type"] != "PT_LOAD":
                continue
            va = int(ph["p_vaddr"])
            off = int(ph["p_offset"])
            fsz = int(ph["p_filesz"])
            if fsz:
                self._segments.append((va, off, fsz))
        flags = int(self.elf.header.e_flags)
        self.abi = "n32" if flags & 0x20 else "o32"
        dyn = self.elf.get_section_by_name(".dynamic")
        if dyn is None:
            raise SdbLayoutError("%s has no .dynamic section" % name)
        self.local_gotno = None
        self.gotsym = None
        for tag in dyn.iter_tags():
            if tag.entry.d_tag == "DT_MIPS_LOCAL_GOTNO":
                self.local_gotno = int(tag.entry.d_val)
            elif tag.entry.d_tag == "DT_MIPS_GOTSYM":
                self.gotsym = int(tag.entry.d_val)
        if self.local_gotno is None or self.gotsym is None:
            raise SdbLayoutError("%s has no MIPS GOT tags" % name)
        got = self.elf.get_section_by_name(".got")
        dsym = self.elf.get_section_by_name(".dynsym")
        if got is None or dsym is None:
            raise SdbLayoutError("%s has no .got/.dynsym" % name)
        text = self.elf.get_section_by_name(".text")
        self.text_lo = int(text["sh_addr"])
        self.text_hi = self.text_lo + int(text["sh_size"])
        self.got_va = int(got["sh_addr"])
        self.got_off = int(got["sh_offset"])
        self.got_size = int(got["sh_size"])
        self.symbols = {}
        for i, sym in enumerate(dsym.iter_symbols()):
            self.symbols[i] = (sym.name, int(sym["st_value"]), int(sym["st_size"]),
                               sym["st_shndx"])

    def word(self, va: int) -> Optional[int]:
        for base, off, size in self._segments:
            if base <= va and va + 4 <= base + size:
                return struct.unpack_from(">I", self.data, off + (va - base))[0]
        return None

    def in_text(self, va: int) -> bool:
        return self.text_lo <= va < self.text_hi

    def is_external(self, name: str) -> bool:
        """True for a name the image imports rather than defines (SHN_UNDEF).

        An imported function still carries the address of its lazy stub in
        ``st_value``, so the address alone does not say "no body here".
        """
        return any(n == name and ndx == "SHN_UNDEF"
                   for n, _v, _s, ndx in self.symbols.values())

    def symbol(self, name: str) -> Tuple[int, int]:
        for _idx, (sym_name, value, size, ndx) in self.symbols.items():
            if sym_name == name and value and ndx != "SHN_UNDEF":
                return value, size
        raise SdbLayoutError("%s has no defined symbol %s" % (self.name, name))

    def slot_value(self, index: int) -> int:
        return struct.unpack_from(">I", self.data, self.got_off + 4 * index)[0]

    def slot_name(self, index: int) -> Optional[str]:
        """The dynamic symbol a .got slot calls, or None for a local slot."""
        if index < self.local_gotno:
            return None
        sym = self.symbols.get(index - self.local_gotno + self.gotsym)
        return sym[0] if sym else None

    def gp_of(self, start: int, size: int) -> int:
        """The ``_gp`` a function runs with, from its ``addu gp,...`` prologue."""
        for k in range(0, min(size, 0x30), 4):
            w = self.word(start + k)
            if w is None or (w >> 26) != 0 or ((w >> 11) & 0x1F) != 28:
                continue
            rs, rt = (w >> 21) & 0x1F, (w >> 16) & 0x1F
            # the constant comes from a register set by lui+addiu; t9 (25) holds
            # the function's own address at entry, so it is the other one
            candidates = [r for r in (rs, rt) if r != 25]
            if not candidates:
                continue
            other = candidates[0]
            hi = lo = None
            for j in range(0, k, 4):
                x = self.word(start + j)
                if x is None:
                    continue
                if (x >> 26) == 0x0F and ((x >> 16) & 0x1F) == other:   # lui
                    hi = x & 0xFFFF
                if (x >> 26) == 0x09 and ((x >> 21) & 0x1F) == other \
                        and ((x >> 16) & 0x1F) == other:                # addiu
                    lo = x & 0xFFFF
            if hi is None or lo is None:
                continue
            hi = hi - 0x10000 if hi & 0x8000 else hi
            lo = lo - 0x10000 if lo & 0x8000 else lo
            return (start + (hi << 16) + lo) & 0xFFFFFFFF
        raise SdbLayoutError("%s: %#x has no _gp prologue" % (self.name, start))


def _simm(w: int) -> int:
    imm = w & 0xFFFF
    return imm - 0x10000 if imm & 0x8000 else imm


def _slot_index(gp: int, imm: int, got_va: int, got_size: int) -> int:
    addr = (gp + imm) & 0xFFFFFFFF
    if not (got_va <= addr < got_va + got_size):
        raise SdbLayoutError("%#x is outside .got" % addr)
    return (addr - got_va) // 4


def _li(w: int) -> Optional[Tuple[int, int]]:
    """(register, value) for a ``li``/``addiu rd,zero,imm``, else None."""
    if (w >> 26) == 0x09 and ((w >> 21) & 0x1F) == 0:
        return (w >> 16) & 0x1F, _simm(w)
    return None


def _stack_consts(img: _Image, start: int, size: int) -> Dict[int, object]:
    """What each stack slot holds, for the constants a prologue spills.

    A value (``li reg,N`` -> ``sw reg,off(sp)``) is recorded as an int; a pointer
    (``addiu rd,<base>,N`` -> ``sw rd,off(sp)``) as ``("<base reg>", N)``, which is
    how N32 hands a codec a struct member: it points a stack slot at ``s1 + N``
    and passes that slot instead of offsetting the base register in place.
    """
    out = {}
    values = {}
    pointers = {}
    for va in range(start, start + size, 4):
        w = img.word(va)
        if w is None:
            continue
        li = _li(w)
        if li is not None:
            values[li[0]] = li[1]
            pointers.pop(li[0], None)
            continue
        if (w >> 26) == 0x09 and ((w >> 21) & 0x1F) != 0:
            pointers[(w >> 16) & 0x1F] = ((w >> 21) & 0x1F, _simm(w))
            values.pop((w >> 16) & 0x1F, None)
            continue
        if (w >> 26) == 0x2B and ((w >> 21) & 0x1F) in _SP_REGS:   # sw rt,off(sp)
            rt = (w >> 16) & 0x1F
            if rt in values:
                out[_simm(w)] = values[rt]
            elif rt in pointers:
                out[_simm(w)] = pointers[rt]
    return out


def _dynsym_name(img: _Image, address: int) -> Optional[str]:
    """The dynamic symbol defined at *address*, if any."""
    for _idx, (name, value, _size, ndx) in img.symbols.items():
        if value == address and ndx != "SHN_UNDEF":
            return name
    return None


def _call_sites(img: _Image, start: int, size: int, gp: int) -> List[Tuple[int, int]]:
    """``(lw/jal address, jalr/jal-delay address)`` for every call in a body."""
    sites = []
    pending = None
    for va in range(start, start + size, 4):
        w = img.word(va)
        if w is None:
            continue
        if (w >> 26) == 0x23 and ((w >> 21) & 0x1F) == 28 \
                and ((w >> 16) & 0x1F) == 25:                     # lw t9,off(gp)
            pending = va
            continue
        if (w >> 26) == 0x03:                                    # jal <target>
            sites.append((va, va))
            pending = None
            continue
        if pending is not None and (w >> 26) == 0 and (w & 0x3F) == 0x09 \
                and ((w >> 21) & 0x1F) == 25:
            sites.append((pending, va))                          # jalr t9
            pending = None
    return sites


def _calls(img: _Image, start: int, size: int, gp: int) -> List[dict]:
    """Every call in a body, with the codec it calls and the member it passes.

    Returns dicts of ``{"at", "codec", "member", "maxsize", "elsize"}``: the call
    site, the dynamic symbol the call reaches (through a .got slot for a shared
    library entry, or a direct ``jal`` for a local one), the struct offset the
    call is given, and the xdr maxsize/element-size arguments where present.
    O32 offsets the struct pointer in place (``addiu a1,a1,N``); N32 points a
    stack slot at ``s1 + N`` and passes the slot, so both shapes are read. An
    argument is looked for anywhere back to the previous call, since N32 sets a
    register far earlier than O32 -- which only ever has to reach the delay slot.
    """
    stack = _stack_consts(img, start, size)
    sites = _call_sites(img, start, size, gp)
    out = []
    prev = start
    for load_at, call_at in sites:
        codec = None
        w = img.word(load_at)
        if (w >> 26) == 0x23:
            codec = img.slot_name(_slot_index(gp, _simm(w), img.got_va,
                                              img.got_size))
        else:
            target = ((load_at + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            codec = _dynsym_name(img, target)
        out.append({
            "at": load_at,
            "codec": codec,
            "member": _call_member(img, call_at, stack),
            "maxsize": _call_arg(img, prev, call_at, stack, 7),
            "elsize": _call_arg(img, prev, call_at, stack, 5),
        })
        prev = call_at + 4
    return out


def _window(img: _Image, before: int, call_at: int) -> List[int]:
    """The addresses of the instructions setting up one call, in order."""
    return list(range(before, call_at + 8, 4))


def _call_member(img: _Image, call_at: int, stack: Dict[int, object]) -> Optional[int]:
    """The struct offset the call at *call_at* passes in a1, if the body states it."""
    member = None
    for va in _window(img, call_at - 12, call_at):
        w = img.word(va)
        if w is None:
            continue
        if (w >> 26) == 0x09 and ((w >> 21) & 0x1F) == 5 \
                and ((w >> 16) & 0x1F) == 5:                        # addiu a1,a1,N
            member = _simm(w)
        elif (w >> 26) == 0x09 and ((w >> 21) & 0x1F) in _SP_REGS \
                and ((w >> 16) & 0x1F) == 5:                        # addiu a1,sp,N
            slot = stack.get(_simm(w))
            if isinstance(slot, tuple):
                member = slot[1]
    return member


def _call_arg(img: _Image, before: int, call_at: int, stack: Dict[int, object],
              reg: int) -> Optional[int]:
    """The last value written to argument register *reg* before the call."""
    value = None
    for va in _window(img, before, call_at):
        w = img.word(va)
        if w is None:
            continue
        li = _li(w)
        if li is not None:
            if li[0] == reg:
                value = li[1]
            continue
        if (w >> 26) == 0x23 and ((w >> 16) & 0x1F) == reg \
                and ((w >> 21) & 0x1F) in _SP_REGS:                 # lw rX,off(sp)
            slot = stack.get(_simm(w))
            if isinstance(slot, int):
                value = slot
            continue
        if (w >> 26) == 0x09 and ((w >> 16) & 0x1F) == reg:
            value = None        # some other value; stop trusting the old one
    return value


def _accessor_offset(img: _Image, start: int, size: int) -> int:
    """The offset of the LAST ``lw`` in the body whose base is not sp/fp/ra/gp.

    Both accessors resolve the symbol first and then load the published field out
    of the resolved entry, so the last such load is the field the caller gets --
    including the N32 element-count accessor, whose load sits in the delay slot
    of a tail ``b`` rather than falling through.
    """
    offset = None
    for va in range(start, start + size, 4):
        w = img.word(va)
        if w is None or (w >> 26) not in (0x23, 0x27):
            continue
        if ((w >> 21) & 0x1F) in _SP_REGS or ((w >> 21) & 0x1F) == 28:
            continue
        offset = _simm(w)
    if offset is None:
        raise SdbLayoutError("%s: %#x reads no field off a resolved entry"
                             % (img.name, start))
    return offset


# ------------------------------------------------------------------ header ---

def _scalar_wire_size(img: _Image, codec: str) -> Optional[int]:
    """Wire bytes one element of *codec* occupies, read from the codec's own body.

    A codec that delegates (``xdr_SDBelementIndex`` -> ``xdr_u_long``) is followed
    one level; one that encodes a struct (``xdr_SDBversionNumber``, two u_shorts)
    is counted by the calls in its body.
    """
    if img.is_external(codec):
        # A codec that lives in libc has no body in this image; one XDR unit.
        return XDR_UNIT
    try:
        start, size = img.symbol(codec)
    except SdbLayoutError:
        return None
    gp = img.gp_of(start, size)
    calls = _calls(img, start, size, gp)
    if calls:
        total = 0
        for call in calls:
            step = _scalar_wire_size(img, call["codec"]) if call["codec"] else None
            if step is None:
                return None
            total += step
        return total
    # no delegate: a leaf codec encodes one XDR unit (4 bytes)
    return XDR_UNIT


def _header_wire(img: _Image) -> Tuple[HeaderField, ...]:
    start, size = img.symbol("xdr_SDBfileHeader")
    gp = img.gp_of(start, size)
    calls = _calls(img, start, size, gp)
    if not calls:
        raise SdbLayoutError("xdr_SDBfileHeader makes no codec calls")
    out = []
    wire = 0
    for call in calls:
        codec = call["codec"]
        if codec is None:
            raise SdbLayoutError("xdr_SDBfileHeader calls a local slot at %#x"
                                 % call["at"])
        if not codec.startswith("xdr_"):
            # a helper called to compute an argument (xdr_SDBfileHeader calls
            # strlen to size its first opaque); it encodes nothing
            continue
        if codec in ("xdr_bytes", "xdr_array"):
            if call["maxsize"] is None:
                raise SdbLayoutError("%s: xdr maxsize not resolved at %#x"
                                     % (img.name, call["at"]))
            if codec == "xdr_bytes":
                room = (call["maxsize"] + 3) & ~3      # a byte bound, padded
            else:
                room = (call.get("elsize") or XDR_UNIT) * call["maxsize"]
            width = XDR_UNIT + room
        elif codec == "xdr_SDBversionNumber":
            width = 2 * XDR_UNIT          # two u_short, one XDR unit each
        else:
            step = _scalar_wire_size(img, codec)
            if step is None:
                raise SdbLayoutError("%s: no wire size for %s" % (img.name, codec))
            width = step
        bound = call["maxsize"] if codec in ("xdr_bytes", "xdr_array") else None
        out.append(HeaderField(codec, wire, width, call["member"], bound))
        wire += width
    return tuple(out)


# --------------------------------------------------------------- type table ---

def _type_table(img: _Image) -> Tuple[Dict[int, str], Dict[int, int]]:
    """``mapTypeToXDRPROC``'s type code -> (codec, element width), from its table.

    The function bounds the code (``sltiu at,<reg>,N``), picks a handler out of a
    jump table, and each handler loads the codec's address from a .got slot and
    stores an element width. The table's base is a literal in the image, so its
    entries are read from the file, not computed from a guess.
    """
    start, size = img.symbol("mapTypeToXDRPROC")
    gp = img.gp_of(start, size)
    table = None
    for va in range(start, start + size, 4):
        w = img.word(va)
        if w is None or (w >> 26) != 0x23 or ((w >> 21) & 0x1F) != 28:
            continue
        rt = (w >> 16) & 0x1F
        base = img.word(gp + _simm(w))
        if base is None:
            continue
        for j in range(va + 4, min(va + 0x1C, start + size), 4):
            x = img.word(j)
            if x is None:
                continue
            # O32 spells the table as `lw rX,imm(base)` -- a literal base word
            # with the bias folded into the load -- and its entries are
            # _gp-relative. N32 adjusts the base with `addiu` and its entries hold
            # the handler's absolute address.
            if (x >> 26) == 0x09 and ((x >> 16) & 0x1F) == rt \
                    and ((x >> 21) & 0x1F) == rt:
                table = (base + _simm(x)) & 0xFFFFFFFF
                break
            if (x >> 26) == 0x23 and ((x >> 21) & 0x1F) == rt:
                table = (base + _simm(x)) & 0xFFFFFFFF
                break
        if table is not None:
            break
    if table is None:
        raise SdbLayoutError("%s: mapTypeToXDRPROC has no jump table" % img.name)

    count = None
    for va in range(start, start + size, 4):
        w = img.word(va)
        if w is not None and (w >> 26) == 0x0B and ((w >> 16) & 0x1F) == 1:
            count = _simm(w)
            break
    if count is None:
        raise SdbLayoutError("%s: mapTypeToXDRPROC has no code bound" % img.name)

    codecs: Dict[int, str] = {}
    widths: Dict[int, int] = {}
    for code in range(count):
        entry = img.word(table + 4 * code)
        if entry is None:
            raise SdbLayoutError("%s: type table ends at %d" % (img.name, code))
        target = (entry + gp) & 0xFFFFFFFF if img.abi == "o32" else entry
        # One handler states its codec and its element width and then branches to
        # the shared tail; the codec load may sit after the branch, in its delay
        # slot (N32 does that), so the delay slot is read before stopping.
        codec = None
        for va in range(target, min(target + 0x20, start + size), 4):
            w = img.word(va)
            if w is None:
                break
            if (w >> 26) == 0x23 and ((w >> 21) & 0x1F) == 28:
                name = img.slot_name(_slot_index(gp, _simm(w), img.got_va,
                                                 img.got_size))
                if name and name.startswith("xdr_"):
                    codec = name
            li = _li(w)
            if li is not None and li[1] in (1, 2, 4, 8):
                widths[code] = li[1]
            if (w >> 26) == 0x04:                      # b -- handler ends here
                delay = img.word(va + 4)
                if delay is not None and (delay >> 26) == 0x23 \
                        and ((delay >> 21) & 0x1F) == 28:
                    name = img.slot_name(_slot_index(gp, _simm(delay),
                                                     img.got_va, img.got_size))
                    if name and name.startswith("xdr_"):
                        codec = name
                break
        if codec:
            codecs[code] = codec
    return codecs, widths


# ---------------------------------------------------------------- the API ---

def read_bytes(name: str, data: bytes) -> SdbSchema:
    """Read one build of the SDB reader out of its bytes."""
    img = _Image(name, data)
    for wanted in ("xdr_SDBsymbolTableEntry", "SDBgetSymbolDatatype",
                   "SDBgetSymbolElementCount", "xdr_SDBsymbolName",
                   "xdr_SDBfileHeader", "mapTypeToXDRPROC"):
        img.symbol(wanted)
    gp = img.gp_of(*img.symbol("xdr_SDBsymbolTableEntry"))

    start, size = img.symbol("xdr_SDBsymbolTableEntry")
    calls = _calls(img, start, size, gp)
    entry = []
    wire = 0
    for call in calls:
        if call["codec"] is None:
            raise SdbLayoutError("xdr_SDBsymbolTableEntry calls a local slot")
        entry.append((call["codec"], wire))
        wire += XDR_UNIT
    if tuple(n for n, _ in entry) != ENTRY_FIELDS:
        raise SdbLayoutError("%s: symbol table entry is %s, expected %s"
                             % (img.name, tuple(n for n, _ in entry), ENTRY_FIELDS))

    offsets = {}
    for fn in ACCESSORS:
        offsets[fn] = _accessor_offset(img, *img.symbol(fn))

    start, size = img.symbol("xdr_SDBsymbolName")
    bound = None
    for va in range(start, start + size, 4):
        li = _li(img.word(va))
        if li is not None and li[0] == 6:        # li a2,N -- xdr_string's maxsize
            bound = li[1]
    if bound is None:
        raise SdbLayoutError("%s: xdr_SDBsymbolName passes no string bound" % img.name)

    codecs, widths = _type_table(img)
    return SdbSchema(
        path=name, abi=img.abi, gp=gp, entry_wire=tuple(entry),
        entry_members=tuple(c["member"] for c in calls),
        datatype_offset=offsets["SDBgetSymbolDatatype"],
        element_count_offset=offsets["SDBgetSymbolElementCount"],
        name_bound=bound, header_wire=_header_wire(img),
        type_codecs=codecs, type_widths=widths)


def read(path: str) -> SdbSchema:
    """Read one build of the SDB reader out of a file."""
    with open(path, "rb") as fh:
        return read_bytes(path, fh.read())


# --------------------------------------------------------------- the corpus ---

VFC_MAGIC = b"\x00\x00\x00\x04sdb "
VFC_RECORD_COUNT = 0x80
VFC_TABLE_END = 0x88


def corpus_field_layout(data: bytes) -> Optional[dict]:
    """The header words a ``vfc-database`` file itself carries, or None.

    The pieces this module's schema has to agree with: the two version numbers
    (each two u_short) at 0x08..0x17, the fixed producer record at 0x18, the
    record count at 0x80, the table end at 0x88 and the header array at 0x8c.
    """
    if len(data) < 0x100 or data[:8] != VFC_MAGIC:
        return None
    words = struct.unpack_from(">12I", data, 0x08)
    count = struct.unpack_from(">I", data, VFC_RECORD_COUNT)[0]
    return {
        "version1": (words[0], words[1]),
        "version2": (words[2], words[3]),
        "producer_len": words[4],
        "record_count": count,
        "table_end": struct.unpack_from(">I", data, VFC_TABLE_END)[0],
        "header_array_count": struct.unpack_from(">I", data, 0x8C)[0],
    }
