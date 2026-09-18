"""pyirix.efs.media — turn a host directory or tar into a mountable EFS image.

This is the "data exchange" front end to :mod:`pyirix.efs.builder`: collect a
host directory tree or a tar archive into an in-memory tree, then hand it to
``mkfs_efs`` so the on-disk format lives in exactly one place (the builder).

IRIX 6.5.5 has no FAT/iso9660 filesystem support, so a host directory cannot be
mounted directly; the only mountable host-side representation is an EFS (or
XFS) image.  These images are read-only snapshots: the guest mounts them ``ro``
like optical media.  To refresh the contents, rebuild and ``change`` the medium
at the QEMU monitor (see ``pyirix_qemu.media``).

Limits enforced here (fail loudly rather than building a silently corrupt
volume): EFS stores each path component's length in a single byte, so a name
must be 1..255 ASCII bytes with no ``/``; non-ASCII names are rejected because
the builder would otherwise substitute ``?`` and store the wrong name.  Special
files (sockets, FIFOs, device nodes) are skipped and recorded, not copied.
"""

from __future__ import annotations

import argparse
import os
import sys
import tarfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from pyirix.efs.builder import mkfs_efs

#: EFS d_namelen is a single byte, so a path component cannot exceed this.
EFS_MAX_NAME = 255


class HostTreeError(ValueError):
    """A host name cannot be represented in EFS."""


def _check_component(name: str) -> None:
    """Reject a path component EFS cannot store faithfully."""
    if not name or name in (".", ".."):
        raise HostTreeError(f"invalid EFS path component: {name!r}")
    if "/" in name:
        raise HostTreeError(f"path component contains '/': {name!r}")
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HostTreeError(
            f"non-ASCII name not representable in EFS: {name!r}"
        ) from exc
    if len(encoded) > EFS_MAX_NAME:
        raise HostTreeError(
            f"name too long for EFS ({len(encoded)} > {EFS_MAX_NAME}): {name!r}"
        )


def _check_path(path: str) -> None:
    for comp in path.strip("/").split("/"):
        _check_component(comp)


@dataclass
class EFSTree:
    """A host tree staged for EFS, keyed by absolute guest path.

    ``files`` maps ``/path`` -> raw bytes, ``symlinks`` maps ``/path`` -> target,
    and ``dirs`` lists every directory (including empty ones).  Parent
    directories of files are created automatically by the builder.
    """

    files: Dict[str, bytes] = field(default_factory=dict)
    symlinks: Dict[str, str] = field(default_factory=dict)
    dirs: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    def add_file(self, path: str, data: bytes) -> None:
        path = "/" + path.lstrip("/")
        _check_path(path)
        self.files[path] = data

    def add_symlink(self, path: str, target: str) -> None:
        path = "/" + path.lstrip("/")
        _check_path(path)
        self.symlinks[path] = target

    def add_dir(self, path: str) -> None:
        path = "/" + path.strip("/")
        if path == "/":
            return
        _check_path(path)
        if path not in self.dirs:
            self.dirs.append(path)

    def write(
        self,
        output_path: str,
        size_blocks: Optional[int] = None,
        with_volume_header: bool = True,
    ) -> str:
        """Build the EFS byte image at *output_path* and return that path.

        ``size_blocks`` overrides the auto-computed EFS size (in 512-byte basic
        blocks); ``with_volume_header`` wraps the EFS partition in an SGI volume
        header so the guest sees it as partition 7 (``dks0d4s7``) like an
        install CD.
        """
        return mkfs_efs(
            output_path,
            files=self.files,
            symlinks=self.symlinks,
            dirs=self.dirs,
            size_blocks=size_blocks,
            with_volume_header=with_volume_header,
            quiet=True,
        )


def collect_directory(root: str) -> EFSTree:
    """Recursively collect *root* into an :class:`EFSTree`.

    Symlinks are stored as EFS symlinks (never followed); regular files are read
    whole; directories are kept even when empty.  Note that this reads all file
    data into memory, which is fine for the media-exchange sizes this targets.
    """
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise HostTreeError(f"not a directory: {root}")

    tree = EFSTree()

    def rel(path: str) -> str:
        return "/" + os.path.relpath(path, root).replace(os.sep, "/")

    def walk(directory: str) -> None:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            path = entry.path
            guest = rel(path)
            if entry.is_symlink():
                tree.add_symlink(guest, os.readlink(path))
            elif entry.is_dir(follow_symlinks=False):
                tree.add_dir(guest)
                walk(path)
            elif entry.is_file(follow_symlinks=False):
                with open(path, "rb") as handle:
                    tree.add_file(guest, handle.read())
            else:
                tree.skipped.append(guest)

    walk(root)
    return tree


def _normalize_tar_member(name: str) -> str:
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.strip("/")


def collect_tar(tar_path: str) -> EFSTree:
    """Collect a tar archive into an :class:`EFSTree` (``r:*`` auto-detects)."""
    if not os.path.isfile(tar_path):
        raise HostTreeError(f"not a file: {tar_path}")

    tree = EFSTree()
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            name = _normalize_tar_member(member.name)
            if not name or name in (".", ".."):
                continue
            guest = "/" + name
            try:
                if member.isdir():
                    tree.add_dir(guest)
                elif member.issym():
                    tree.add_symlink(guest, member.linkname)
                elif member.isfile() or member.islnk():
                    extracted = tf.extractfile(member)
                    data = extracted.read() if extracted is not None else b""
                    tree.add_file(guest, data)
                else:
                    tree.skipped.append(guest)
            except HostTreeError:
                raise
    return tree


def build_efs_from_directory(
    root: str,
    output_path: str,
    size_blocks: Optional[int] = None,
    with_volume_header: bool = True,
) -> EFSTree:
    """Build an EFS image from host directory *root*; return the used tree."""
    tree = collect_directory(root)
    tree.write(output_path, size_blocks, with_volume_header)
    return tree


def build_efs_from_tar(
    tar_path: str,
    output_path: str,
    size_blocks: Optional[int] = None,
    with_volume_header: bool = True,
) -> EFSTree:
    """Build an EFS image from tar archive *tar_path*; return the used tree."""
    tree = collect_tar(tar_path)
    tree.write(output_path, size_blocks, with_volume_header)
    return tree


@dataclass
class BuildSummary:
    """Human-readable result of a CLI build."""

    path: str
    files: int
    dirs: int
    symlinks: int
    skipped: int
    size_bytes: int

    def line(self) -> str:
        return (
            f"{self.path}: {self.files} files, {self.dirs} dirs, "
            f"{self.symlinks} symlinks, {self.skipped} skipped, "
            f"{self.size_bytes} bytes"
        )


def summarize(tree: EFSTree, output_path: str) -> BuildSummary:
    return BuildSummary(
        path=output_path,
        files=len(tree.files),
        dirs=len(tree.dirs),
        symlinks=len(tree.symlinks),
        skipped=len(tree.skipped),
        size_bytes=os.path.getsize(output_path),
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pyirix.efs.media",
        description="Build a mountable read-only EFS image from a host "
        "directory or tar (for IRIX guests with no FAT/iso9660 support).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dir", metavar="ROOT", help="host directory to package")
    source.add_argument("--tar", metavar="TAR", help="tar archive to package")
    parser.add_argument("output", help="EFS image path to create")
    parser.add_argument(
        "--blocks",
        type=int,
        default=None,
        help="EFS size in 512-byte blocks (default: auto from content)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="omit the SGI volume header (raw EFS partition)",
    )
    args = parser.parse_args(argv)

    try:
        if args.dir:
            tree = build_efs_from_directory(
                args.dir, args.output, args.blocks, not args.raw
            )
        else:
            tree = build_efs_from_tar(
                args.tar, args.output, args.blocks, not args.raw
            )
    except (HostTreeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(summarize(tree, args.output).line())
    for path in tree.skipped:
        print(f"  skipped (special file): {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
