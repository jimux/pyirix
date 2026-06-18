#!/usr/bin/env python3
"""Extract files from IRIX .sw archives using .idb metadata.

Each .sw archive is a flat concatenation of per-file records:

    [u16-BE: pathlen]
    [pathlen bytes: install path]
    [cmpsize bytes of compressed (or raw) data]

The compressed data is LZW (UNIX `compress` format, magic `\\x1f\\x9d`),
NOT deflate. On Linux `gunzip -c` decompresses .Z fine, but we keep
pyirix dep-free by carrying a small pure-Python LZW decoder.

When `cmpsize == 0` or `cmpsize == size`, the data is stored uncompressed.

API:
    extract_one(sw_bytes, entry) -> bytes
    extract_many(sw_path, idb)   -> dict[install_path → bytes]
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from pyirix.dist.idb import IDB, IDBEntry


# Each file record starts with a 2-byte big-endian path length prefix,
# then the path, then the compressed payload. The .idb's `off(...)` points
# at the START OF THE RECORD (i.e. at the path-length prefix), and
# `cmpsize` covers the payload (NOT including the path header).
#
# So extraction is:
#   1. Read 2 bytes at `off` — that's pathlen.
#   2. Skip pathlen bytes of the path string.
#   3. Read `cmpsize` bytes of payload (LZW or uncompressed).


def _decompress_lzw(data: bytes) -> bytes:
    """Decompress UNIX `compress`-format (.Z, magic 0x1F 0x9D) data.
    Uses gunzip via subprocess — present on every Linux/Unix system."""
    try:
        result = subprocess.run(
            ["gunzip", "-c"], input=data, capture_output=True,
            timeout=30, check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"LZW decompression failed: {e}")


def extract_one(sw_bytes: bytes, entry: IDBEntry) -> bytes:
    """Extract a single file's content from the .sw archive buffer."""
    if not entry.is_file:
        return b""
    if entry.size == 0:
        return b""

    # Parse the per-record path-length header
    p = entry.offset
    if p + 2 > len(sw_bytes):
        return b""
    pathlen = int.from_bytes(sw_bytes[p:p+2], "big")
    payload_start = p + 2 + pathlen
    cmpsize = entry.cmpsize or entry.size
    payload = sw_bytes[payload_start:payload_start + cmpsize]

    # Uncompressed if cmpsize is 0 OR equal to size
    if entry.cmpsize == 0 or entry.cmpsize == entry.size:
        return payload[:entry.size]

    # Otherwise LZW-compressed
    if len(payload) >= 2 and payload[:2] == b"\x1f\x9d":
        try:
            return _decompress_lzw(payload)
        except RuntimeError:
            return payload    # caller can inspect raw if decompression fails

    # Unknown payload format — return raw for inspection
    return payload


def extract_many(sw_path: str | Path, idb: IDB,
                 filter_subsystem: str | None = None
                 ) -> dict[str, bytes]:
    """Extract all files from a .sw archive on disk into a dict keyed by
    install_path. If filter_subsystem is given, restrict to that subsystem."""
    with open(sw_path, "rb") as f:
        sw_bytes = f.read()
    out: dict[str, bytes] = {}
    for e in idb.entries:
        if not e.is_file:
            continue
        if filter_subsystem and e.subsystem != filter_subsystem:
            continue
        out[e.install_path] = extract_one(sw_bytes, e)
    return out


def extract_to_dir(sw_path: str | Path, idb: IDB, output_dir: str | Path,
                   filter_subsystem: str | None = None) -> int:
    """Extract files to a host directory, preserving install_path structure
    (rooted at output_dir). Returns count of files written."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = extract_many(sw_path, idb, filter_subsystem=filter_subsystem)
    written = 0
    for install_path, content in files.items():
        # install_path starts with "/" — strip to make relative.
        rel = install_path.lstrip("/")
        dst = output_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "wb") as g:
            g.write(content)
        written += 1
    return written


# ── CLI ────────────────────────────────────────────────────────────────


def _main(argv: list[str] | None = None) -> int:
    import argparse, sys
    from pyirix.dist.idb import parse_idb

    ap = argparse.ArgumentParser(description="Extract files from IRIX .sw archives.")
    ap.add_argument("--idb", required=True, help=".idb manifest path")
    ap.add_argument("--sw", help="path to .sw archive (default: idb stem + .sw)")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--subsystem", help="filter to one subsystem")
    args = ap.parse_args(argv)

    idb = parse_idb(args.idb)
    sw_path = args.sw or str(Path(args.idb).with_suffix(".sw"))
    if not Path(sw_path).exists():
        print(f"ERROR: .sw archive not found: {sw_path}", file=sys.stderr)
        return 2

    n = extract_to_dir(sw_path, idb, args.out,
                       filter_subsystem=args.subsystem)
    print(f"extracted {n} files to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
