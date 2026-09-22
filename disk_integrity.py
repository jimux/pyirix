"""Golden-integrity check: detect guest files whose DATA was silently lost.

A disk can be structurally perfect (``qemu-img check`` clean, XFS headers valid)
and still have lost data: when a VM is stopped without flushing the guest page
cache — e.g. QEMU's monitor ``quit``, which is a hard power-off, or a harness
close path that does the same — the guest filesystem commits a file's metadata
but the DATA blocks never reach the disk. The file then reappears at its correct
path, inode and size, with its content wiped (empty, all zero, or all
whitespace). Nothing about the disk looks wrong until something tries to run or
read that file.

This module reads every regular file under a set of directories straight from
the guest XFS (host-side, no boot) and classifies those wiped-data signatures.
An optional *pristine base* is used two ways: to suppress false positives (a
file that is legitimately empty/whitespace in the base is not a finding) and to
annotate each finding with the base's state.

Provenance
----------
Extracted from ``tmp/ip20/sweep.py`` (lane indigo-ip20-3) after that lane found
two IP20 goldens whose ``/usr/sbin/inst`` and ``/usr/sbin/showprods`` (and five
more binaries) had been wiped by the unflushed-write path. Promoted to the
library per the one-offs convention (see ``archive/README.md``); harness fix in
``pyirix_qemu.install.irix.clean_guest_shutdown``.

Usage
-----
    from pyirix.disk_integrity import scan, format_report
    rep = scan("/path/golden.qcow2", base="/path/pristine-base.qcow2")
    print(format_report(rep))
    assert rep.passed
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .xfs.image import open_disk_image, find_xfs_partition
from .xfs.superblock import read_superblock
from .xfs import operations as ops
from .xfs.inode import read_inode, read_file_data

# Directories swept by default — the ones that hold programs and libraries a
# wiped file would break. Extend via the `dirs` argument for other layouts.
DEFAULT_DIRS = [
    "/usr/sbin", "/usr/lib", "/usr/bin", "/usr/etc",
    "/etc", "/sbin", "/usr/gfx", "/usr/lib32",
]

# Files that are legitimately all-whitespace (or trivially small) on a healthy
# IRIX disk. These are reported as `allowlisted` in the report — never silently
# skipped — so a reader can see the check considered and cleared them.
ALLOWLIST = {
    "/usr/lib/sendmail.cf_m4/siteconfig/uucp.ucbarpa.m4":
        "legitimately a 1-byte newline on a healthy IRIX disk "
        "(present as such in the pristine base)",
}

WIPED_EMPTY = "wiped-empty"
WIPED_ZERO = "wiped-zero"
WIPED_WHITESPACE = "wiped-whitespace"

_WS = (0x20, 0x09, 0x0A, 0x0D)
_SAMPLE = 8192


def classify(data: bytes, size: int) -> str | None:
    """Return the wiped-data signature for a file's content, or None if healthy.

    ``size`` is the inode size; a non-empty size with no data read is the
    strongest signature (the data fork is gone while the metadata survived).
    """
    if size > 0 and not data:
        return WIPED_EMPTY
    if not data:
        return None
    sample = data[:_SAMPLE]
    if all(b == 0 for b in sample):
        return WIPED_ZERO
    if all(b in _WS for b in sample):
        return WIPED_WHITESPACE
    return None


@dataclass
class Finding:
    path: str
    kind: str
    size: int
    allowlisted: bool = False
    reason: str = ""


@dataclass
class Report:
    image: str
    base: str | None = None
    scanned: int = 0
    dirs: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)

    @property
    def wiped(self) -> list[Finding]:
        """Genuinely wiped files (allowlisted entries excluded)."""
        return [f for f in self.findings if not f.allowlisted]

    @property
    def passed(self) -> bool:
        return not self.wiped


def _open_xfs(path):
    """Yield (fileobj, part_offset, sb) for a qcow2/raw SGI disk or a bare XFS.

    Handles both an SGI volume (XFS in a partition, found via the volume header)
    and a bare XFS image (superblock at offset 0) so test fixtures built with
    ``mkfs_xfs(with_volume_header=False)`` work unchanged.
    """
    return _open_xfs_cm(path)


class _open_xfs_cm:
    def __init__(self, path):
        self._path = path
        self._cm = None

    def __enter__(self):
        self._cm = open_disk_image(self._path)
        f = self._cm.__enter__()
        part = find_xfs_partition(f)
        offset = part[0] if part else 0
        sb = read_superblock(f, offset)
        if sb is None:
            self._cm.__exit__(None, None, None)
            raise ValueError(f"no XFS superblock found in {self._path}")
        return f, offset, sb

    def __exit__(self, *a):
        return self._cm.__exit__(*a)


def _base_index(base):
    """Return a dict path -> md5 of a pristine base, or None."""
    if not base:
        return None
    idx: dict[str, str] = {}
    with _open_xfs(base) as (f, offset, sb):
        for d in DEFAULT_DIRS:
            try:
                ino = ops.resolve_path(f, offset, sb, d)
            except Exception:
                continue
            if ino is None:
                continue
            res: list = []
            ops.list_recursive(f, offset, sb, ino, d, res, max_entries=200000)
            for e in res:
                if e.get("type") != "-" or e.get("size", 0) == 0:
                    continue
                p = e["path"]
                try:
                    ci = ops.resolve_path(f, offset, sb, p)
                    inode = read_inode(f, offset, sb, ci)
                    idx[p] = hashlib.md5(
                        read_file_data(f, offset, sb, inode)).hexdigest()
                except Exception:
                    pass
    return idx


def scan(image, dirs=None, base=None, max_read=200 * 1024 * 1024,
         allowlist=None) -> Report:
    """Sweep `image` for wiped-data files. See module docstring."""
    dirs = list(dirs) if dirs else list(DEFAULT_DIRS)
    allowlist = ALLOWLIST if allowlist is None else allowlist
    rep = Report(image=str(image), base=str(base) if base else None, dirs=dirs)
    base_idx = _base_index(base) if base else None

    with _open_xfs(image) as (f, offset, sb):
        for d in dirs:
            try:
                ino = ops.resolve_path(f, offset, sb, d)
            except Exception:
                ino = None
            if ino is None:
                rep.unread.append(f"{d} (absent)")
                continue
            res: list = []
            ops.list_recursive(f, offset, sb, ino, d, res, max_entries=200000)
            for e in res:
                if e.get("type") != "-" or e.get("size", 0) == 0:
                    continue
                p = e["path"]
                size = e.get("size", 0)
                if size > max_read:
                    rep.unread.append(p)
                    continue
                rep.scanned += 1
                try:
                    ci = ops.resolve_path(f, offset, sb, p)
                    inode = read_inode(f, offset, sb, ci)
                    data = read_file_data(f, offset, sb, inode)
                except Exception as ex:
                    rep.findings.append(
                        Finding(p, f"read-fail: {ex}", size))
                    continue
                kind = classify(data, size)
                if kind is None:
                    continue
                # A file whose content is byte-identical to the pristine base is
                # legitimately like this (e.g. a template that is all whitespace),
                # not a clobber.
                if base_idx is not None and p in base_idx and \
                        base_idx[p] == hashlib.md5(data).hexdigest():
                    continue
                allow = p in allowlist
                rep.findings.append(
                    Finding(p, kind, size, allowlisted=allow,
                            reason=allowlist.get(p, "")))
    return rep


def format_report(rep: Report) -> str:
    lines = [f"## Golden integrity sweep — `{rep.image}`"]
    if rep.base:
        lines.append(f"  base: `{rep.base}`")
    lines.append(f"  scanned {rep.scanned} regular files under: {', '.join(rep.dirs)}")
    if rep.unread:
        lines.append(f"  not read (>{len(rep.unread)} entries, e.g. >max_read or absent): "
                     f"{rep.unread[:5]}{' …' if len(rep.unread) > 5 else ''}")
    lines.append("")
    if not rep.findings:
        lines.append("  [PASS] no wiped-data signatures found")
    else:
        for fnd in rep.findings:
            tag = "ALLOWLISTED" if fnd.allowlisted else "WIPED"
            mark = "·" if fnd.allowlisted else "✗"
            lines.append(f"  [{tag}] {mark} {fnd.kind} size={fnd.size} {fnd.path}")
            if fnd.allowlisted and fnd.reason:
                lines.append(f"           reason: {fnd.reason}")
    lines.append("")
    lines.append(f"**Overall: {'PASS' if rep.passed else 'FAIL'} — "
                 f"{len(rep.wiped)} wiped, "
                 f"{len(rep.findings) - len(rep.wiped)} allowlisted**")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    import sys

    img = sys.argv[1]
    b = sys.argv[2] if len(sys.argv) > 2 else None
    print(format_report(scan(img, base=b)))
