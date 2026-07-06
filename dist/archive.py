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

import os
import subprocess
from pathlib import Path

from pyirix.dist.idb import IDB, IDBEntry, parse_idb


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


def archive_of_entry(entry: IDBEntry) -> str:
    """Return the archive file an IDB entry lives in (e.g. 'demos_O2.swII').

    A subsystem name is `<product>.<archive_ext>.<tag>` (e.g.
    `demos_O2.swII.Birth_of_O2`), so the archive file is everything before the
    final `.tag`. Files of one product are split across `.sw`, `.swII`, `.man`,
    etc.; each entry's byte offset is relative to ITS archive, so extracting all
    entries from a single `.sw` corrupts the ones that live in `.swII`.
    """
    ss = entry.subsystem or ""
    return ss.rsplit(".", 1)[0] if "." in ss else ss


def _reconstruct_offsets(sw_bytes: bytes, entries: list, default_header: int = 13):
    """Set entry.offset for archives whose idb omitted `off(...)`.

    Record layout: [u16-BE pathlen][path][payload], payload = cmpsize bytes when
    compressed else size bytes; the archive starts with a short `im001Vxxx Pxx`
    header. Directory/symlink entries carry no archive bytes. We auto-detect the
    header length by locating the first entry's stored path, then walk cumulatively.
    """
    if not entries:
        return
    first = entries[0].install_path.lstrip("/").encode("latin-1", "replace")
    idx = sw_bytes.find(first, 0, 1024)
    off = (idx - 2) if idx >= 2 else default_header
    for e in entries:
        e.offset = off
        pathlen = len(e.install_path.lstrip("/"))
        payload = e.cmpsize if e.cmpsize > 0 else e.size
        off += 2 + pathlen + payload


def extract_product(install_dir: str | Path, product: str, output_dir: str | Path,
                    include_man: bool = False) -> dict:
    """Reconstruct a full installed tree for one inst product, spanning ALL its
    archive files (`<product>.sw`, `.swII`, ...).

    `install_dir` holds `<product>.idb` plus the `<product>.sw*` archives (the
    layout inside an SGI inst CD's `install/` or `dist/` directory). Files,
    symlinks and directories are materialized under `output_dir` at their
    install_path. Returns `{files, links, dirs, archives, missing_archives}`.

    This is the correct multi-archive counterpart to `extract_to_dir`, which only
    reads a single `.sw`.
    """
    from collections import defaultdict

    install_dir = Path(install_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    idb = parse_idb(str(install_dir / f"{product}.idb"))

    # group file entries by their owning archive
    by_archive: dict[str, list] = defaultdict(list)
    links = dirs = 0
    for e in idb.entries:
        if e.is_dir:
            d = output_dir / e.install_path.lstrip("/")
            try:
                d.mkdir(parents=True, exist_ok=True)
                dirs += 1
            except (FileExistsError, NotADirectoryError, PermissionError):
                # path already materialized as a symlink/file by an earlier entry
                # (e.g. IRIX EOE ships /usr/adm both ways) — leave it as-is
                pass
        elif e.is_symlink:
            dst = output_dir / e.install_path.lstrip("/")
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                if dst.is_symlink() or dst.exists():
                    dst.unlink()
                os.symlink(e.target or "", dst)
                links += 1
            except OSError:
                pass
        elif e.is_file:
            by_archive[archive_of_entry(e)].append(e)

    files = 0
    archives_used = []
    missing = []
    for archive, entries in by_archive.items():
        if archive.endswith(".man") and not include_man:
            continue
        ap = install_dir / archive
        if not ap.exists():
            missing.append(archive)
            continue
        sw_bytes = ap.read_bytes()
        archives_used.append(archive)
        # Some inst products (notably the high-end Onyx/InfiniteReality demo
        # discs, archive ext .demo/.other/.portalis) ship idbs WITHOUT an
        # `off(...)` token, so every entry.offset is 0. Reconstruct the per-archive
        # cumulative byte offsets from the record layout in that case.
        if entries and all(e.offset == 0 for e in entries):
            _reconstruct_offsets(sw_bytes, entries)
        for e in entries:
            content = extract_one(sw_bytes, e)
            rel = e.install_path.lstrip("/")
            dst = output_dir / rel
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                with open(dst, "wb") as g:
                    g.write(content)
                files += 1
            except (FileExistsError, NotADirectoryError, IsADirectoryError, OSError):
                # a parent path collides with an earlier symlink/file entry; skip
                continue
    return {
        "files": files, "links": links, "dirs": dirs,
        "archives": sorted(archives_used), "missing_archives": sorted(missing),
        "product": product,
    }


def build_tar(sw_path: str | Path, idb: IDB, out_path: str | Path,
              subsystems=None, gzip: bool = True) -> dict:
    """Build a tar mirroring install media: decompress each .sw file entry and
    emit it at its ``install_path`` with the IDB's **mode, owner/group, and
    symlinks** preserved, synthesizing parent directories explicitly so a live
    ``untar`` on an IRIX guest reproduces permissions exactly.

    ``subsystems`` (a set/list of subsystem names) restricts what is shipped;
    ``None`` ships every entry. Returns ``{files, links, dirs, bytes}``.

    Why explicit dir entries + owner/group: an IRIX install is owned root:sys
    with specific modes; a plain ``tar`` of just the files would let the guest's
    umask and missing intermediate dirs corrupt the permission set. This carries
    every directory (0755 root:sys) and each file's exact ``mode & 07777``, which
    is what makes the live-untar desktop graft boot-faithful. Extracted from the
    one-off ``build_desktop_eoe_tar.py``.
    """
    import io
    import tarfile

    keep = set(subsystems) if subsystems is not None else None
    with open(sw_path, "rb") as f:
        sw_bytes = f.read()

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_files = n_links = 0
    seen_dirs: set[str] = set()
    mode = "w:gz" if gzip else "w"

    with tarfile.open(out_path, mode, format=tarfile.GNU_FORMAT) as tf:
        def ensure_dirs(install_path: str):
            cur = ""
            for p in install_path.lstrip("/").split("/")[:-1]:
                cur = cur + "/" + p if cur else p
                if cur in seen_dirs:
                    continue
                seen_dirs.add(cur)
                ti = tarfile.TarInfo(name=cur)
                ti.type = tarfile.DIRTYPE
                ti.mode, ti.uid, ti.gid = 0o755, 0, 0
                ti.uname, ti.gname = "root", "sys"
                tf.addfile(ti)

        for e in idb.entries:
            if keep is not None and e.subsystem not in keep:
                continue
            rel = e.install_path.lstrip("/")
            if e.type == "f":
                data = extract_one(sw_bytes, e)
                ensure_dirs(e.install_path)
                ti = tarfile.TarInfo(name=rel)
                ti.size = len(data)
                ti.mode = e.mode & 0o7777
                ti.uid, ti.gid = 0, 0
                ti.uname = e.owner or "root"
                ti.gname = e.group or "sys"
                ti.type = tarfile.REGTYPE
                tf.addfile(ti, io.BytesIO(data))
                n_files += 1
            elif e.type == "l" and e.target:
                ensure_dirs(e.install_path)
                ti = tarfile.TarInfo(name=rel)
                ti.type = tarfile.SYMTYPE
                ti.linkname = e.target
                ti.mode, ti.uid, ti.gid = 0o777, 0, 0
                ti.uname, ti.gname = "root", "sys"
                tf.addfile(ti)
                n_links += 1

    return {"files": n_files, "links": n_links, "dirs": len(seen_dirs),
            "bytes": out_path.stat().st_size}


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
