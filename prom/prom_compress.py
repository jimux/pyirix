"""
Decompress the compressed PROM segments used by SGI firmware containers.

The two schemes and their headers are taken from the in-tree sources shipped
with the IO4 PROM tooling:

  * RLE   -- ``irix-657m/stand/arcs/tools/promcvt/rle.c`` (+ ``rle.h``);
             header ``prom_rle_hdr_t``, magic ``_RLE``.
  * LZW   -- ``irix-657m/stand/arcs/tools/promcvt/promcvt.c`` and
             ``irix-657m/stand/arcs/IO4prom/segldr/{segment.c,lzw.h}``; the
             compressed payload is a UNIX ``compress(1)`` stream (codec
             ``IO4prom/segldr/compress.c``) behind a 16-byte ``prom_lzw_hdr_t``
             (magic ``_LZW``).

Both headers carry the true (decompressed) length and a byte-sum checksum, and
both decoders verify them -- a mismatch raises rather than returning suspect
bytes.  This is stdlib-only so ``pyirix`` stays standalone.
"""

import struct
from typing import Any, Dict, List, Union

RLE_MAGIC = 0x5F524C45  # '_RLE'
LZW_MAGIC = 0x5F4C5A57  # '_LZW'

_HDR = 16


class DecompressError(ValueError):
    """A compressed segment is malformed or fails its length/checksum check."""


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _sum32(data: Union[bytes, bytearray]) -> int:
    return sum(data) & 0xFFFFFFFF


def rle_decompress(data: bytes) -> bytes:
    """
    Decode a ``prom_rle_hdr_t`` + run-length stream (``rle.c``).

    The stream is a sequence of tokens: a zero byte introduces a run
    (``00 count value`` -> ``value`` repeated ``count + 1`` times, except
    ``00 00`` which is a single zero); any non-zero byte is itself, once.
    """
    if len(data) < _HDR:
        raise DecompressError("RLE segment shorter than its header")
    if _u32(data, 0) != RLE_MAGIC:
        raise DecompressError(
            "RLE magic is 0x{:08x}, expected 0x{:08x}".format(_u32(data, 0), RLE_MAGIC))
    real_length = _u32(data, 4)
    real_cksum = _u32(data, 8)

    body = data[_HDR:]
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        cur = body[i]
        i += 1
        if cur == 0:
            if i >= n:
                raise DecompressError("RLE stream truncated in a run token")
            count = body[i]
            i += 1
            if count == 0:
                out.append(0)
            else:
                if i >= n:
                    raise DecompressError("RLE stream truncated before a run value")
                value = body[i]
                i += 1
                out.extend(bytes([value]) * (count + 1))
        else:
            out.append(cur)
        if len(out) > real_length:
            raise DecompressError("RLE run decompresses beyond the declared length")

    if len(out) != real_length:
        raise DecompressError(
            "RLE length {} != stored {}".format(len(out), real_length))
    if _sum32(out) != real_cksum:
        raise DecompressError(
            "RLE checksum 0x{:08x} != stored 0x{:08x}".format(_sum32(out), real_cksum))
    return bytes(out)


def rle_compress(data: bytes) -> bytes:
    """
    Encode with the inverse of :func:`rle_decompress`, per ``compress_block``.

    Provided so the decoder can be round-trip tested against the same in-tree
    source (there is no RLE fixture in the library).  Emits ``00 00`` for a
    lone zero and ``00 count value`` for runs of two or more.
    """
    out = bytearray()
    out += struct.pack(">IIII", RLE_MAGIC, len(data), _sum32(data), 0)

    i = 0
    n = len(data)
    while i < n:
        value = data[i]
        j = i + 1
        while j < n and data[j] == value and (j - i) < 256:
            j += 1
        run = j - i
        if value != 0:
            out += bytes([0, run - 1, value]) if run > 1 else bytes([value])
        else:
            out += b"\x00\x00" if run == 1 else bytes([0, run - 1, 0])
        i = j
    return bytes(out)


def lzw_decompress(data: bytes) -> bytes:
    """
    Decode a ``prom_lzw_hdr_t`` + UNIX ``compress(1)`` stream.

    ``promcvt.c`` lays the stream out as the 16-byte header, then the standard
    3-byte ``compress`` header (``1f 9d`` + a flags byte: low 5 bits maxbits,
    high bit block mode), then the codes.  ``lzw_padding`` counts trailing pad
    bytes to drop.  The code packing and the width-change accounting follow
    ``compress.c``'s ``getcode``/``decompress`` exactly.
    """
    if len(data) < _HDR + 3:
        raise DecompressError("LZW segment shorter than its header")
    if _u32(data, 0) != LZW_MAGIC:
        raise DecompressError(
            "LZW magic is 0x{:08x}, expected 0x{:08x}".format(_u32(data, 0), LZW_MAGIC))
    real_length = _u32(data, 4)
    real_cksum = _u32(data, 8)
    padding = _u32(data, 12)
    if padding > len(data) - _HDR:
        raise DecompressError("LZW padding exceeds the segment")

    body = data[_HDR:len(data) - padding]
    if len(body) < 3 or body[0] != 0x1F or body[1] != 0x9D:
        raise DecompressError("LZW payload is not a compress(1) stream")
    flags = body[2]
    maxbits = flags & 0x1F
    block_mode = bool(flags & 0x80)
    if maxbits < 9 or maxbits > 16:
        raise DecompressError("LZW maxbits {} out of range".format(maxbits))
    maxmaxcode = 1 << maxbits
    clear_code = 256
    first_entry = 257

    blob = body[3:]
    prefix: List[int] = [0] * 65536
    suffix: List[int] = list(range(256)) + [0] * (65536 - 256)

    # Mirrors compress.c's getcode(): codes are packed n_bits bits at a time,
    # but the reader consumes n_bits-byte groups and, on a code-width change,
    # drops the rest of the current group and re-reads at the new width -- the
    # inverse of the encoder's putcode() group padding.  A flat bitstream
    # desyncs wherever the encoder padded.  `bp` picks the final partial byte
    # (by+1 when <8 bits remain, else by+2), exactly as the C does.
    st: Dict[str, Any] = {"pos": 0, "buf": b"", "size": 0, "offset": 0,
                          "n_bits": 9, "maxcode": (1 << 9) - 1, "free": 0,
                          "clear": 0}

    def getcode() -> int:
        if st["clear"] > 0 or st["offset"] >= st["size"] or st["free"] > st["maxcode"]:
            if st["free"] > st["maxcode"]:
                st["n_bits"] += 1
                st["maxcode"] = (maxmaxcode if st["n_bits"] == maxbits
                                 else (1 << st["n_bits"]) - 1)
            if st["clear"] > 0:
                st["n_bits"] = 9
                st["maxcode"] = (1 << 9) - 1
                st["clear"] = 0
            st["buf"] = blob[st["pos"]:st["pos"] + st["n_bits"]]
            st["pos"] += st["n_bits"]
            if not st["buf"]:
                return -1
            st["size"] = (len(st["buf"]) << 3) - (st["n_bits"] - 1)
            st["offset"] = 0
        buf = st["buf"]
        off = st["offset"]
        by = off >> 3
        r = off & 7
        code = buf[by] >> r
        bp = by + 1
        bits = st["n_bits"] - (8 - r)
        r = 8 - r
        if bits >= 8:
            if bp < len(buf):
                code |= buf[bp] << r
            bp += 1
            r += 8
            bits -= 8
        if bits > 0 and bp < len(buf):
            code |= (buf[bp] & ((1 << bits) - 1)) << r
        st["offset"] = off + st["n_bits"]
        return code

    st["free"] = first_entry if block_mode else 256
    out = bytearray()
    stack: List[int] = []

    fin = oldcode = getcode()
    if oldcode < 0:
        return b""
    if fin > 255:
        raise DecompressError("LZW first code {} is not a literal".format(fin))
    out.append(fin)

    while True:
        code = getcode()
        if code < 0:
            break
        if code == clear_code and block_mode:
            st["clear"] = 1
            st["free"] = first_entry - 1
            code = getcode()
            if code < 0:
                break
        incode = code
        if code >= st["free"]:
            if code != st["free"]:
                raise DecompressError("LZW code {} out of range".format(code))
            stack.append(fin)
            code = oldcode
        depth = 0
        while code >= 256:
            stack.append(suffix[code])
            code = prefix[code]
            depth += 1
            if depth > 65536:
                raise DecompressError("LZW prefix chain is cyclic")
        fin = code
        stack.append(fin)
        while stack:
            out.append(stack.pop())

        if st["free"] < maxmaxcode:
            prefix[st["free"]] = oldcode
            suffix[st["free"]] = fin
            st["free"] += 1
        oldcode = incode

    if len(out) < real_length:
        raise DecompressError(
            "LZW produced {} bytes, fewer than the declared {}".format(
                len(out), real_length))
    out = out[:real_length]
    if _sum32(out) != real_cksum:
        raise DecompressError(
            "LZW checksum 0x{:08x} != stored 0x{:08x}".format(
                _sum32(out), real_cksum))
    return bytes(out)


def decode_segment(seg_type: int, data: bytes) -> bytes:
    """
    Dispatch on the ``SFLAG_COMPMASK`` compression bits (sys/EVEREST/promhdr.h).

    ``SFLAG_UNCOMPRESSED`` returns the bytes unchanged; RLE/LZW are decoded.
    """
    comp = seg_type & 0x6
    if comp == 0x0:
        return data
    if comp == 0x2:
        return rle_decompress(data)
    if comp == 0x4:
        return lzw_decompress(data)
    raise DecompressError("unknown compression bits 0x{:x}".format(comp))
