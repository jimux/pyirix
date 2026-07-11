#!/usr/bin/env python3
"""File-tree providers — a uniform read interface over the several source
media the asset importer accepts.

Every asset source (extracted dist tree, plain root tree, IRIX disk image,
EFS/ISO CD, untarred tardist) ultimately looks like a *tree of files* that
we walk by path. Rather than special-case each medium in the importer, we
expose them all through one small `FileProvider` interface:

    listdir(rel)  -> [(name, kind)]     kind in {'f','d','l'}
    read(rel)     -> bytes
    readlink(rel) -> str
    exists(rel)   -> bool
    is_dir(rel)   -> bool

`rel` is always a POSIX path *relative to the tree root*, with no leading
slash (root itself is "" or "."). The importer's extraction engine
(``engine.py``) is written purely against this interface, so dist-media
detection, glob matching and symlink handling are written once and work
for host directories, XFS partitions and EFS partitions alike.

Three concrete providers live here:

* ``HostFileProvider``  — a directory on the local filesystem (used
  directly for dist/plain trees, and for temp dirs that tardist/ISO
  sources extract into).
* ``XfsFileProvider``   — an open IRIX XFS partition (installed disk).
* ``EfsFileProvider``   — an open IRIX EFS partition (CD / install media).

The XFS/EFS providers wrap the existing, well-tested pyirix readers
(``pyirix.xfs.operations`` / ``pyirix.efs.reader``); they add no new
on-disk parsing, only the uniform surface.
"""

from __future__ import annotations

import os
import stat
from typing import Iterable

from pyirix.xfs import operations as _xfsops
from pyirix.xfs.inode import (
    read_inode as _xfs_read_inode,
    read_file_data as _xfs_read_file_data,
    read_symlink as _xfs_read_symlink,
)
from pyirix.xfs.directory import read_dir_entries as _xfs_read_dir_entries
from pyirix.xfs.constants import S_IFMT, S_IFDIR, S_IFREG, S_IFLNK

from pyirix.efs import reader as _efs


# ── kind helpers ───────────────────────────────────────────────────────

def _norm(rel: str) -> str:
    """Normalize a provider-relative path to a clean, slash-free-leading form."""
    rel = (rel or "").replace("\\", "/").strip("/")
    return rel


class FileProvider:
    """Abstract read interface. See module docstring."""

    #: short label used in receipts ("host", "xfs", "efs")
    kind_label = "abstract"

    def listdir(self, rel: str) -> list[tuple[str, str]]:
        raise NotImplementedError

    def read(self, rel: str) -> bytes:
        raise NotImplementedError

    def readlink(self, rel: str) -> str:
        raise NotImplementedError

    def exists(self, rel: str) -> bool:
        raise NotImplementedError

    def is_dir(self, rel: str) -> bool:
        raise NotImplementedError

    # ── shared walk: yields (rel, kind) for every node under `top` ──
    def walk(self, top: str) -> Iterable[tuple[str, str]]:
        """Depth-first walk of the subtree rooted at `top`.

        Yields (rel, kind) for each entry (files, dirs, symlinks). Symlinks
        are yielded as-is and NOT descended into (we preserve them verbatim).
        `top` itself is yielded first if it exists.
        """
        top = _norm(top)
        if not self.exists(top):
            return
        # Emit the root of the subtree.
        if self.is_dir(top):
            yield (top, "d")
            stack = [top]
            while stack:
                d = stack.pop()
                try:
                    entries = self.listdir(d)
                except Exception:
                    continue
                for name, kind in sorted(entries):
                    child = f"{d}/{name}" if d else name
                    if kind == "d":
                        yield (child, "d")
                        stack.append(child)
                    else:
                        yield (child, kind)
        else:
            # `top` is a file or symlink itself
            yield (top, "l" if self._is_link(top) else "f")

    def _is_link(self, rel: str) -> bool:
        return False


# ── host filesystem ─────────────────────────────────────────────────────

class HostFileProvider(FileProvider):
    kind_label = "host"

    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    def _abs(self, rel: str) -> str:
        rel = _norm(rel)
        return self.root if not rel else os.path.join(self.root, rel)

    def listdir(self, rel: str) -> list[tuple[str, str]]:
        out = []
        p = self._abs(rel)
        try:
            names = os.listdir(p)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            return out
        for name in names:
            full = os.path.join(p, name)
            if os.path.islink(full):
                out.append((name, "l"))
            elif os.path.isdir(full):
                out.append((name, "d"))
            else:
                out.append((name, "f"))
        return out

    def read(self, rel: str) -> bytes:
        with open(self._abs(rel), "rb") as f:
            return f.read()

    def readlink(self, rel: str) -> str:
        return os.readlink(self._abs(rel))

    def exists(self, rel: str) -> bool:
        return os.path.lexists(self._abs(rel))

    def is_dir(self, rel: str) -> bool:
        p = self._abs(rel)
        return os.path.isdir(p) and not os.path.islink(p)

    def _is_link(self, rel: str) -> bool:
        return os.path.islink(self._abs(rel))


# ── IRIX XFS partition ───────────────────────────────────────────────────

class XfsFileProvider(FileProvider):
    """Read-only view over an open XFS partition.

    `f` is a file object open at byte 0 of the whole image; `part_offset`
    is the XFS partition byte offset; `sb` is the parsed superblock.
    """

    kind_label = "xfs"

    def __init__(self, f, part_offset: int, sb: dict):
        self.f = f
        self.po = part_offset
        self.sb = sb
        self._ino_cache: dict[str, int | None] = {}

    def _ino(self, rel: str):
        rel = _norm(rel)
        if rel in self._ino_cache:
            return self._ino_cache[rel]
        ino = _xfsops.resolve_path(self.f, self.po, self.sb, "/" + rel)
        self._ino_cache[rel] = ino
        return ino

    def _inode(self, rel: str):
        ino = self._ino(rel)
        if ino is None:
            return None
        return _xfs_read_inode(self.f, self.po, self.sb, ino)

    def listdir(self, rel: str) -> list[tuple[str, str]]:
        inode = self._inode(rel)
        if not inode or (inode["di_mode"] & S_IFMT) != S_IFDIR:
            return []
        out = []
        for name, child_ino in _xfs_read_dir_entries(self.f, self.po, self.sb, inode):
            child = _xfs_read_inode(self.f, self.po, self.sb, child_ino)
            if not child:
                continue
            ft = child["di_mode"] & S_IFMT
            kind = "d" if ft == S_IFDIR else ("l" if ft == S_IFLNK else "f")
            out.append((name, kind))
            # seed the child inode cache to avoid a second resolve
            cr = f"{_norm(rel)}/{name}" if _norm(rel) else name
            self._ino_cache[cr] = child_ino
        return out

    def read(self, rel: str) -> bytes:
        inode = self._inode(rel)
        if not inode:
            raise FileNotFoundError(rel)
        return _xfs_read_file_data(self.f, self.po, self.sb, inode)

    def readlink(self, rel: str) -> str:
        inode = self._inode(rel)
        if not inode:
            raise FileNotFoundError(rel)
        t = _xfs_read_symlink(self.f, self.po, self.sb, inode)
        if isinstance(t, bytes):
            t = t.decode("latin-1", errors="replace")
        return t

    def exists(self, rel: str) -> bool:
        return self._ino(rel) is not None

    def is_dir(self, rel: str) -> bool:
        inode = self._inode(rel)
        return bool(inode) and (inode["di_mode"] & S_IFMT) == S_IFDIR

    def _is_link(self, rel: str) -> bool:
        inode = self._inode(rel)
        return bool(inode) and (inode["di_mode"] & S_IFMT) == S_IFLNK


# ── IRIX EFS partition ───────────────────────────────────────────────────

_EFS_S_IFMT = 0o170000
_EFS_S_IFDIR = 0o040000
_EFS_S_IFLNK = 0o120000


class EfsFileProvider(FileProvider):
    """Read-only view over an open EFS partition (CD / install media)."""

    kind_label = "efs"

    def __init__(self, f, part_offset: int, sb: dict):
        self.f = f
        self.po = part_offset
        self.sb = sb
        self._ino_cache: dict[str, int | None] = {"": _efs.EFS_ROOT_INODE}

    def _ino(self, rel: str):
        rel = _norm(rel)
        if rel in self._ino_cache:
            return self._ino_cache[rel]
        # Resolve component by component from the nearest cached ancestor.
        parts = [p for p in rel.split("/") if p]
        cur = _efs.EFS_ROOT_INODE
        acc = ""
        for part in parts:
            inode = _efs.read_inode(self.f, self.po, self.sb, cur)
            if not inode or (inode["mode"] & _EFS_S_IFMT) != _EFS_S_IFDIR:
                self._ino_cache[rel] = None
                return None
            found = None
            for name, ino in _efs.read_dir_entries(self.f, self.po, self.sb, inode):
                if name == part:
                    found = ino
                    break
            if found is None:
                self._ino_cache[rel] = None
                return None
            cur = found
            acc = f"{acc}/{part}" if acc else part
            self._ino_cache[acc] = cur
        return cur

    def _inode(self, rel: str):
        ino = self._ino(rel)
        if ino is None:
            return None
        return _efs.read_inode(self.f, self.po, self.sb, ino)

    def listdir(self, rel: str) -> list[tuple[str, str]]:
        inode = self._inode(rel)
        if not inode or (inode["mode"] & _EFS_S_IFMT) != _EFS_S_IFDIR:
            return []
        out = []
        base = _norm(rel)
        for name, child_ino in _efs.read_dir_entries(self.f, self.po, self.sb, inode):
            child = _efs.read_inode(self.f, self.po, self.sb, child_ino)
            if not child:
                continue
            ft = child["mode"] & _EFS_S_IFMT
            kind = "d" if ft == _EFS_S_IFDIR else ("l" if ft == _EFS_S_IFLNK else "f")
            out.append((name, kind))
            cr = f"{base}/{name}" if base else name
            self._ino_cache[cr] = child_ino
        return out

    def read(self, rel: str) -> bytes:
        inode = self._inode(rel)
        if not inode:
            raise FileNotFoundError(rel)
        return _efs.read_file_data(self.f, self.po, self.sb, inode)

    def readlink(self, rel: str) -> str:
        inode = self._inode(rel)
        if not inode:
            raise FileNotFoundError(rel)
        return _efs.read_symlink_target(self.f, self.po, self.sb, inode)

    def exists(self, rel: str) -> bool:
        return self._ino(rel) is not None

    def is_dir(self, rel: str) -> bool:
        inode = self._inode(rel)
        return bool(inode) and (inode["mode"] & _EFS_S_IFMT) == _EFS_S_IFDIR

    def _is_link(self, rel: str) -> bool:
        inode = self._inode(rel)
        return bool(inode) and (inode["mode"] & _EFS_S_IFMT) == _EFS_S_IFLNK
