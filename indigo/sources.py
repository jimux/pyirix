#!/usr/bin/env python3
"""Source-format detection + adaptation for the asset importer.

A *source* is whatever the user points the importer at:

  1. an extracted inst **dist tree**   (dir with ``<product>.idb`` + ``.sw*``)
  2. an **EFS** CD / install image      (raw/qcow2 with an EFS partition)
  3. an **ISO9660** CD image
  4. a **.tardist**                     (tar of a dist tree)
  5. an IRIX **disk image**             (qcow2/raw with an XFS or EFS root)
  6. a plain extracted **root tree**    (dir containing ``usr/…``)

`open_source(path)` sniffs the format and returns a `Source`, a context
manager that exposes a single `FileProvider` (see ``providers.py``) plus an
`identity` dict for the receipt. The importer's extraction engine then runs
uniformly against that provider — it auto-detects *dist-media* vs
*installed-tree* layout, so cases 1/4 (dist trees) and 2/3/5/6 (which may be
either) all funnel through the same code.

ISO and tardist sources materialise into a temp dir (via ``xorriso`` /
``tarfile``) and hand back a `HostFileProvider`; the temp dir is removed on
context exit. EFS/XFS disk images are read in place (no full extraction).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tarfile
import tempfile
from contextlib import ExitStack
from pathlib import Path

from pyirix.indigo.providers import (
    FileProvider, HostFileProvider, XfsFileProvider, EfsFileProvider,
)


class SourceError(Exception):
    pass


# ── format sniffing ──────────────────────────────────────────────────────

_QCOW2_MAGIC = b"QFI\xfb"
_VHMAGIC = 0x0BE5A941           # SGI volume header magic
_XFS_SB_MAGIC = 0x58465342      # 'XFSB'
_EFS_MAGIC = 0x072959
_EFS_MAGIC_NEW = 0x07295A


def _is_dist_tree(path: str) -> bool:
    """A dir holding at least one ``<product>.idb`` (+ sibling ``.sw``)."""
    p = Path(path)
    if not p.is_dir():
        return False
    for f in p.iterdir():
        if f.suffix == ".idb" and f.is_file():
            # require a sibling .sw* archive to avoid false positives
            stem = f.stem
            if any((p / f"{stem}.sw").exists() or
                   sib.name.startswith(stem + ".sw")
                   for sib in p.iterdir()):
                return True
    return False


def _is_plain_root(path: str) -> bool:
    p = Path(path)
    return p.is_dir() and (p / "usr").is_dir()


def _sniff_file(path: str) -> str:
    """Classify a regular file: 'disk', 'iso', 'tardist', or '' (unknown)."""
    name = path.lower()
    if name.endswith((".tardist", ".tar", ".tar.gz", ".tgz")):
        return "tardist"
    with open(path, "rb") as f:
        head = f.read(64 * 1024)
    if head[:4] == _QCOW2_MAGIC:
        return "disk"
    # SGI volume header?
    if len(head) >= 4 and struct.unpack(">I", head[:4])[0] == _VHMAGIC:
        return "disk"
    # bare XFS superblock at offset 0?
    if len(head) >= 4 and struct.unpack(">I", head[:4])[0] == _XFS_SB_MAGIC:
        return "disk"
    # ISO9660: 'CD001' at 0x8001
    with open(path, "rb") as f:
        f.seek(0x8001)
        if f.read(5) == b"CD001":
            return "iso"
    # tar magic at 257?
    if head[257:262] == b"ustar":
        return "tardist"
    # bare EFS image (superblock at block 1, magic at +28)
    if len(head) >= 1024:
        magic = struct.unpack(">I", head[512 + 28:512 + 32])[0]
        if magic in (_EFS_MAGIC, _EFS_MAGIC_NEW):
            return "disk"
    return ""


# ── Source objects ───────────────────────────────────────────────────────

class Source:
    """Base: an opened source exposing one `FileProvider`."""

    stype = "abstract"

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._stack = ExitStack()
        self._provider: FileProvider | None = None
        self.identity: dict = {}

    def __enter__(self) -> "Source":
        self._open()
        return self

    def __exit__(self, *exc):
        self._stack.close()
        return False

    def _open(self):
        raise NotImplementedError

    @property
    def provider(self) -> FileProvider:
        assert self._provider is not None, "source not opened"
        return self._provider

    def _base_identity(self) -> dict:
        st = os.stat(self.path)
        return {
            "type": self.stype,
            "path": self.path,
            "name": os.path.basename(self.path.rstrip("/")),
            "size": st.st_size if os.path.isfile(self.path) else None,
            "mtime": int(st.st_mtime),
        }


class DistTreeSource(Source):
    stype = "dist"

    def _open(self):
        self._provider = HostFileProvider(self.path)
        self.identity = self._base_identity()


class PlainTreeSource(Source):
    stype = "plaintree"

    def _open(self):
        self._provider = HostFileProvider(self.path)
        self.identity = self._base_identity()


class TardistSource(Source):
    stype = "tardist"

    def _open(self):
        tmp = self._stack.enter_context(
            tempfile.TemporaryDirectory(prefix="indigo_tardist_",
                                        dir=_scratch_dir()))
        with tarfile.open(self.path) as tf:
            _safe_extractall(tf, tmp)
        root = _descend_single(tmp)
        self._provider = HostFileProvider(root)
        self.identity = self._base_identity()
        self.identity["extracted_root"] = root


class IsoSource(Source):
    stype = "iso"

    def _open(self):
        tmp = self._stack.enter_context(
            tempfile.TemporaryDirectory(prefix="indigo_iso_",
                                        dir=_scratch_dir()))
        _extract_iso(self.path, tmp)
        root = _descend_single(tmp)
        self._provider = HostFileProvider(root)
        self.identity = self._base_identity()


class DiskImageSource(Source):
    """qcow2/raw image with an XFS or EFS filesystem (installed root OR
    dist/CD media). Read in place — no whole-image extraction."""

    stype = "disk"

    def _open(self):
        # Import lazily to keep module import cheap.
        from pyirix.xfs.image import (
            open_disk_image, read_vh, detect_filesystem,
        )
        from pyirix.xfs.superblock import read_superblock as xfs_read_sb
        from pyirix.efs import reader as efs

        f = self._stack.enter_context(open_disk_image(self.path))
        parts = _candidate_partitions(f, read_vh)
        chosen = None
        for po in parts:
            fs = detect_filesystem(f, po)
            if fs == "xfs":
                sb = xfs_read_sb(f, po)
                if sb:
                    self._provider = XfsFileProvider(f, po, sb)
                    chosen = ("xfs", po)
                    break
            elif fs == "efs":
                sb = efs.read_superblock(f, po)
                if sb:
                    self._provider = EfsFileProvider(f, po, sb)
                    chosen = ("efs", po)
                    break
        if self._provider is None:
            raise SourceError(f"no XFS/EFS filesystem found in {self.path}")
        self.identity = self._base_identity()
        self.identity["fs"] = chosen[0]
        self.identity["part_offset"] = chosen[1]


def _candidate_partitions(f, read_vh) -> list[int]:
    """Byte offsets to probe for a filesystem: every non-empty VH partition
    (in table order, filesystem partitions preferred), else offset 0."""
    offs: list[int] = []
    vh = read_vh(f)
    if vh:
        # Prefer real fs partitions (types 7=EFS/older-root, 10=XFS) before
        # whole-volume(6)/volhdr(0) entries.
        ranked = []
        for pt in vh.get("pt", []):
            if pt["nblks"] <= 0:
                continue
            t = pt["type"]
            rank = {10: 0, 7: 1}.get(t, 5)
            ranked.append((rank, pt["firstlbn"] * 512))
        ranked.sort(key=lambda x: x[0])
        offs = [o for _, o in ranked]
    if 0 not in offs:
        offs.append(0)
    return offs


# ── helpers ──────────────────────────────────────────────────────────────

def _scratch_dir() -> str:
    """Project-local scratch for temp extraction (falls back to system tmp)."""
    for cand in ("tmp/indigo-import", "../tmp/indigo-import"):
        p = Path(cand)
        if p.parent.exists():
            p.mkdir(parents=True, exist_ok=True)
            return str(p)
    return tempfile.gettempdir()


def _safe_extractall(tf: tarfile.TarFile, dest: str):
    dest_abs = os.path.abspath(dest)
    for m in tf.getmembers():
        target = os.path.abspath(os.path.join(dest, m.name))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            raise SourceError(f"unsafe tar member path: {m.name}")
    tf.extractall(dest)


def _extract_iso(path: str, dest: str):
    import subprocess
    if shutil.which("xorriso"):
        subprocess.run(
            ["xorriso", "-osirrox", "on", "-indev", path,
             "-extract", "/", dest],
            check=True, capture_output=True, timeout=1800,
        )
        return
    for tool in ("7z", "bsdtar"):
        if shutil.which(tool):
            if tool == "7z":
                subprocess.run(["7z", "x", "-y", f"-o{dest}", path],
                               check=True, capture_output=True, timeout=1800)
            else:
                subprocess.run(["bsdtar", "-xf", path, "-C", dest],
                               check=True, capture_output=True, timeout=1800)
            return
    raise SourceError("ISO extraction needs xorriso/7z/bsdtar (none found)")


def _descend_single(root: str) -> str:
    """If `root` wraps a single subdir (common for tardist/ISO), descend into
    it so detection sees the real tree. Stops at the first meaningful level."""
    cur = root
    for _ in range(4):
        try:
            entries = [e for e in os.listdir(cur)
                       if not e.startswith(".")]
        except OSError:
            break
        # already looks like a tree?
        if _is_dist_tree(cur) or _is_plain_root(cur):
            return cur
        if len(entries) == 1 and os.path.isdir(os.path.join(cur, entries[0])):
            cur = os.path.join(cur, entries[0])
            continue
        break
    return cur


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── entry point ──────────────────────────────────────────────────────────

def open_source(path: str) -> Source:
    """Detect the source format at `path` and return an (unopened) Source.
    Use as a context manager: ``with open_source(p) as src: src.provider``."""
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(path):
        raise SourceError(f"source not found: {path}")

    if os.path.isdir(path):
        if _is_dist_tree(path):
            return DistTreeSource(path)
        if _is_plain_root(path):
            return PlainTreeSource(path)
        raise SourceError(
            f"directory is neither a dist tree (*.idb) nor a root tree "
            f"(usr/): {path}")

    kind = _sniff_file(path)
    if kind == "disk":
        return DiskImageSource(path)
    if kind == "iso":
        return IsoSource(path)
    if kind == "tardist":
        return TardistSource(path)
    raise SourceError(f"unrecognised source file format: {path}")
