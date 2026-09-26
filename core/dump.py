"""SGI/IRIX KERNEL crash-dump reader (the ``sys/dump.h`` format, not userland cores).

A userland IRIX core is ``struct coreout`` (handled by ``pyirix_qemu.coredump``).
A KERNEL crash dump is different: ``/hw/.../partition/1`` block 0 holds a
``dump_hdr_t`` (magic ``"CrshDump"``, ``DUMP_MAGIC`` 0x4372736844756d70), followed
by ``dump_dir_ent_t`` blocks ``{phys_addr, compr_len, flags}`` whose data is
usually RLE-compressed (``DUMP_RLE``) physical memory.

This module parses that structure and recovers, with no VM boot: the kernel
release/uname, the panic string, and the panic's ``PC`` and ``ep`` (the saved
exception-frame pointer, the kernel's ``panicefr``).  Those feed straight into
``sgi_irix_crash_analyze`` (which symbolizes EPC/Cause/BadVAddr from text).

Scope note: the GPR frame itself lives at ``ep``, a mapped kernel VA on the
fixed kernel-stack page; extracting ``ra``/``sp``/``a0`` from it needs a VA->PA
translation that this reader does NOT do (the stack page is dynamically
allocated).  See progress notes.

Format provenance: ``sys/dump.h`` and ``os/vmdump.c`` ``compress_block()`` in the
IRIX 6.5 source tree.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from pyirix.xfs.image import open_disk_image, read_vh

DUMP_MAGIC = 0x4372736844756D70  # "CrshDump"
DUMP_VERSION = 4

# dump_dir_ent_s.flags bits (sys/dump.h)
DUMP_RAW = 0x000
DUMP_RLE = 0x001
DUMP_COMPMASK = 0x003
DUMP_TYPEMASK = 0xFF0
DUMP_END = 0x0800

# dump_hdr_t field offsets (big-endian).  time_t is 32-bit on IRIX o32.
_OFF_MAGIC = 0
_OFF_VERSION = 8
_OFF_PG_SZ = 12
_OFF_PHYSMEM = 16
_OFF_CRASH_TIME = 20
_OFF_SIZE = 24
_OFF_PAGES = 28
_OFF_HDR_SZ = 32
_OFF_UNAME = 36
_UNAME_LEN = 257 * 5
_OFF_PANIC = _OFF_UNAME + _UNAME_LEN          # 1321
_PANIC_LEN = 80
_OFF_PUTBUF = _OFF_PANIC + _PANIC_LEN          # 1401
_PUTBUF_LEN = 2048

_PANIC_RE = re.compile(
    r"PANIC:\s*CPU\s*(\d+):\s*([^\n]*)\n"
    r"PC:\s*0x([0-9a-fA-F]+)\s+ep:\s*0x([0-9a-fA-F]+)")


@dataclass
class DumpHeader:
    version: int
    page_size: int
    physmem_mb: int
    crash_time: int
    dump_size: int
    dump_pages: int
    hdr_size: int
    uname: str
    panic: str


@dataclass
class CrashInfo:
    header: DumpHeader
    cpu: Optional[int] = None
    panic_msg: Optional[str] = None
    pc: Optional[int] = None
    ep: Optional[int] = None
    panic_block_phys: Optional[int] = None
    panic_block_offset: Optional[int] = None
    #: decoded memory blocks seen, as (phys_addr, flags, byte_length)
    blocks: List[Tuple[int, int, int]] = field(default_factory=list)

    def to_crash_text(self) -> str:
        """The panic block's text — feed to ``sgi_irix_crash_analyze``."""
        parts = [f"PANIC: CPU {self.cpu}: {self.panic_msg}"]
        if self.pc is not None and self.ep is not None:
            parts.append(f"PC: 0x{self.pc:x} ep: 0x{self.ep:x}")
        return "\n".join(parts)


def rle_decode(data: bytes) -> bytes:
    """Decode the IRIX dump RLE stream (vmdump.c ``compress_block`` inverse).

    A non-zero byte is a literal; a zero byte is an escape followed by
    ``(count, value)`` meaning ``count + 1`` copies of ``value``.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        i += 1
        if b != 0:
            out.append(b)
        else:
            if i + 1 >= n:
                break
            count = data[i]
            value = data[i + 1]
            i += 2
            out += bytes([value]) * (count + 1)
    return bytes(out)


def parse_header(buf: bytes) -> DumpHeader:
    """Parse a ``dump_hdr_t`` from the first bytes of the dump partition."""
    if len(buf) < _OFF_PUTBUF:
        raise ValueError("not a crash dump: too short for dump_hdr_t")
    magic = struct.unpack(">Q", buf[_OFF_MAGIC:_OFF_MAGIC + 8])[0]
    if magic != DUMP_MAGIC:
        raise ValueError(f"not a crash dump: magic {magic:#x} != {DUMP_MAGIC:#x}")
    (version, pgsz, physmem, ctime, dsize, dpages, hdrsz) = struct.unpack(
        ">7I", buf[_OFF_VERSION:_OFF_HDR_SZ + 4])
    uname = buf[_OFF_UNAME:_OFF_UNAME + _UNAME_LEN].split(b"\0")[0].decode("latin-1")
    panic = buf[_OFF_PANIC:_OFF_PANIC + _PANIC_LEN].split(b"\0")[0].decode("latin-1")
    return DumpHeader(version, pgsz, physmem, ctime, dsize, dpages, hdrsz,
                      uname, panic)


def find_crash_partition(f) -> int:
    """Byte offset of the crash-dump partition, located by the DUMP_MAGIC.

    Prefers the partition whose first block is a dump header (usually pt[1]);
    falls back to pt[1] if the header cannot be read, so the caller still gets a
    useful error.
    """
    vh = read_vh(f)
    if not vh:
        raise ValueError("no SGI volume header on this image")
    candidates = [i for i, pt in enumerate(vh["pt"]) if pt["nblks"] > 0]
    for i in candidates:
        off = vh["pt"][i]["firstlbn"] * 512
        if off <= 0:
            continue
        f.seek(off)
        if f.read(8) == struct.pack(">Q", DUMP_MAGIC):
            return off
    if len(vh["pt"]) > 1 and vh["pt"][1]["nblks"] > 0:
        return vh["pt"][1]["firstlbn"] * 512
    raise ValueError("no crash-dump partition found")


def iter_blocks(image: str, decode: bool = True,
                max_blocks: int = 0) -> Iterator[Tuple[int, int, bytes]]:
    """Yield ``(phys_addr, flags, data)`` for each directory block.

    ``decode=True`` RLE-decompresses (and, when the compressed length is what is
    stored, returns the decompressed bytes).  Stops at a ``DUMP_END`` entry.
    """
    with open_disk_image(image) as f:
        base = find_crash_partition(f)
        f.seek(base)
        head = f.read(_OFF_PUTBUF)
        hdr = parse_header(head)
        f.seek(base + hdr.hdr_size)
        count = 0
        while True:
            ent = f.read(16)
            if len(ent) < 16:
                break
            addr_hi, addr_lo, length, flags = struct.unpack(">IIii", ent)
            data = f.read(length) if length > 0 else b""
            if decode and (flags & DUMP_COMPMASK) == DUMP_RLE:
                data = rle_decode(data)
            yield ((addr_hi << 32) | addr_lo), flags, data
            count += 1
            if flags & DUMP_END:
                break
            if max_blocks and count >= max_blocks:
                break


def read_dump(image: str) -> CrashInfo:
    """Parse the dump: header + panic (cpu/message/PC/ep) + block inventory."""
    with open_disk_image(image) as f:
        base = find_crash_partition(f)
        f.seek(base)
        hdr = parse_header(f.read(_OFF_PUTBUF))
    info = CrashInfo(header=hdr, panic_msg=hdr.panic)

    # The header's dmp_panic_str has the message but not PC/ep; the full console
    # text (a DIRECT block) carries the "PC: .. ep: .." line.
    for addr, _flags, data in iter_blocks(image):
        info.blocks.append((addr, _flags, len(data)))
        m = _PANIC_RE.search(data.decode("latin-1", "replace"))
        if m:
            info.cpu = int(m.group(1))
            info.panic_msg = m.group(2).strip()
            info.pc = int(m.group(3), 16)
            info.ep = int(m.group(4), 16)
            info.panic_block_phys = addr
            info.panic_block_offset = m.start()
            break
    return info
