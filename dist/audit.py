#!/usr/bin/env python3
"""Audit an installed IRIX system against the .idb manifests of its packages.

inst's package database lives at /var/inst/<product>/. After install, the
files inst CLAIMS to have installed are those listed in /var/inst's
tracking — and the EXPECTED file set is what the dist's .idb declares.

For each product registered in /var/inst:
  - Find the matching .idb in a dist source.
  - For every `f` (regular file) entry in that .idb, check whether the
    file is present on the installed disk at its install_path AND has
    the expected size.
  - Report deltas: missing, wrong size, mode mismatch.

Catches the "registered but didn't extract" pattern: package metadata
is in /var/inst (so inst won't reinstall it) but the actual files
aren't on disk.

CLI:
    python3 -m pyirix.dist.audit \\
        --disk vm_instances/ip54-fresh/disk.qcow2 \\
        --dist-image software_library/.../combined.img \\
        [--product desktop_eoe]            # audit just one product
        [--json out.json]                  # emit machine-readable report
        [--missing-only]                   # text mode: show only failures
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# We import lazily inside functions to keep --help fast and avoid forcing
# the heavy sgi_fs/pyirix.xfs imports on bare tests.


# ── Data classes ────────────────────────────────────────────────────────


@dataclass
class FileResult:
    path: str
    expected_size: int
    expected_mode: int
    actual_size: int = -1
    actual_mode: int = -1
    ok: bool = False
    reason: str = ""        # "missing" | "size_mismatch" | "type_mismatch" | ""


@dataclass
class ProductAudit:
    product: str
    idb_source: str = ""
    expected_files: int = 0
    expected_bytes: int = 0
    present_files: int = 0
    present_bytes: int = 0
    missing_files: int = 0
    size_mismatches: int = 0
    type_mismatches: int = 0
    results: list[FileResult] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        if not self.expected_files:
            return 0.0
        return 100.0 * self.present_files / self.expected_files

    @property
    def is_complete(self) -> bool:
        return self.expected_files > 0 and self.missing_files == 0 \
            and self.size_mismatches == 0 and self.type_mismatches == 0


@dataclass
class AuditReport:
    disk: str
    dist_image: str
    products: list[ProductAudit] = field(default_factory=list)

    def summary(self) -> str:
        total = len(self.products)
        complete = sum(1 for p in self.products if p.is_complete)
        partial = sum(1 for p in self.products if not p.is_complete
                      and p.present_files > 0)
        empty = sum(1 for p in self.products if p.present_files == 0)
        return (f"audit: {total} products — {complete} complete, "
                f"{partial} partial, {empty} empty")


# ── Disk inspection ─────────────────────────────────────────────────────


def _list_installed_products(disk_path: str) -> list[str]:
    """Read /var/inst/ on the installed disk; return product names.

    inst's per-product tracking varies by IRIX install variant:
      - On some installs, each product is a FILE (binary product descriptor,
        e.g. /var/inst/4Dwm holding `pd001V650P00...` magic + subsystem records)
      - On others, each product is a DIRECTORY containing version-stamped
        records (e.g. /var/inst/4Dwm/6.5.5m/...).
    Both layouts indicate "product is installed". We enumerate either —
    excluding only dot-prefixed metadata files like .rqsfiles, .checkpoint,
    .machine_inventory, .swmgrrc.
    """
    from sgi_mcp.sgi_fs import (open_disk_image, find_xfs_partition,
        xfs_read_superblock, _xfs_resolve_path, xfs_read_inode,
        xfs_read_dir_entries, S_IFMT, S_IFDIR, S_IFREG)

    # Per-install special-cased non-product entries that ARE files
    # but aren't packages we want to audit:
    NONPRODUCT_FILES = {
        "INSTLOG", "inst.lock", "machfile", "resources", "userlist.exc",
        "help1",
    }

    with open_disk_image(disk_path) as f:
        part = find_xfs_partition(f)
        if not part:
            return []
        off, _ = part
        sb = xfs_read_superblock(f, off)
        if not sb:
            return []
        ino = _xfs_resolve_path(f, off, sb, "/var/inst")
        if ino is None:
            return []
        inode = xfs_read_inode(f, off, sb, ino)
        if (inode["di_mode"] & S_IFMT) != S_IFDIR:
            return []
        entries = xfs_read_dir_entries(f, off, sb, inode)
        products = []
        for name, child_ino in entries:
            if name in (".", "..") or name.startswith("."):
                continue
            if name in NONPRODUCT_FILES:
                continue
            child_inode = xfs_read_inode(f, off, sb, child_ino)
            if not child_inode:
                continue
            ftype = child_inode["di_mode"] & S_IFMT
            # Accept either dir (versioned-subtree layout) or regular
            # file (descriptor-blob layout). Anything else (symlink,
            # device node) is suspicious — skip.
            if ftype in (S_IFDIR, S_IFREG):
                products.append(name)
        return sorted(products)


def _stat_on_disk(disk_path: str, paths: list[str]) -> dict[str, tuple[int, int]]:
    """For each path in paths, return (size, mode_bits) if it exists on
    the disk; otherwise omit. Opens the disk ONCE for batched stat — much
    faster than calling fs_info N times.

    Returns {path: (size, mode)}.
    """
    from sgi_mcp.sgi_fs import (open_disk_image, find_xfs_partition,
        xfs_read_superblock, _xfs_resolve_path, xfs_read_inode)

    out: dict[str, tuple[int, int]] = {}
    with open_disk_image(disk_path) as f:
        part = find_xfs_partition(f)
        if not part:
            return out
        off, _ = part
        sb = xfs_read_superblock(f, off)
        if not sb:
            return out
        # Cache resolved inodes for parent-dir prefixes to avoid re-walking
        # /usr/bin/X11/ from scratch for every file under it.
        for path in paths:
            ino = _xfs_resolve_path(f, off, sb, path)
            if ino is None:
                continue
            inode = xfs_read_inode(f, off, sb, ino)
            if not inode:
                continue
            out[path] = (inode.get("di_size", 0), inode.get("di_mode", 0))
    return out


# ── Dist-image .idb discovery ───────────────────────────────────────────


def _find_idb_in_dist_image(dist_image: str, product: str) -> bytes | None:
    """Search the combined dist EFS image for `<product>.idb`. Returns
    the file contents (bytes) on first match, or None if not found.

    Walks every per-CD subdirectory under /.
    """
    from sgi_mcp.sgi_fs import (open_disk_image, find_efs_partition,
        efs_read_superblock, efs_read_inode, efs_read_dir_entries,
        efs_read_file_data, EFS_ROOT_INODE, S_IFMT, S_IFDIR)

    target = f"{product}.idb"

    with open_disk_image(dist_image) as f:
        part = find_efs_partition(f)
        if not part:
            return None
        off, _ = part
        sb = efs_read_superblock(f, off)
        if not sb:
            return None
        root = efs_read_inode(f, off, sb, EFS_ROOT_INODE)
        if not root:
            return None
        for top_name, top_ino in efs_read_dir_entries(f, off, sb, root):
            if top_name in (".", ".."):
                continue
            sub_inode = efs_read_inode(f, off, sb, top_ino)
            if not sub_inode:
                continue
            if (sub_inode["mode"] & S_IFMT) != S_IFDIR:
                continue
            for name, ino in efs_read_dir_entries(f, off, sb, sub_inode):
                if name == target:
                    inode = efs_read_inode(f, off, sb, ino)
                    if not inode:
                        continue
                    return efs_read_file_data(f, off, sb, inode)
    return None


# ── Auditor ─────────────────────────────────────────────────────────────


def audit_product(disk_path: str, dist_image: str, product: str
                  ) -> ProductAudit | None:
    """Audit a single product. Returns None if its .idb can't be found."""
    from pyirix.dist.idb import parse_idb_bytes

    raw = _find_idb_in_dist_image(dist_image, product)
    if not raw:
        return None
    idb = parse_idb_bytes(raw, product=product)

    file_entries = [e for e in idb.entries if e.is_file]
    audit = ProductAudit(
        product=product,
        idb_source=dist_image,
        expected_files=len(file_entries),
        expected_bytes=sum(e.size for e in file_entries),
    )

    # Batched stat
    paths = [e.install_path for e in file_entries]
    stats = _stat_on_disk(disk_path, paths)

    for e in file_entries:
        info = stats.get(e.install_path)
        result = FileResult(
            path=e.install_path,
            expected_size=e.size,
            expected_mode=e.mode,
        )
        if info is None:
            result.reason = "missing"
            audit.missing_files += 1
        else:
            actual_size, actual_mode = info
            result.actual_size = actual_size
            result.actual_mode = actual_mode
            # XFS stores full mode including type bits — strip to perms.
            actual_perms = actual_mode & 0o7777
            # File-type bits: 0o100000 = S_IFREG. Anything else is a
            # type-mismatch (e.g. directory at a file's path).
            if (actual_mode & 0o170000) != 0o100000:
                result.reason = "type_mismatch"
                audit.type_mismatches += 1
            elif actual_size != e.size:
                result.reason = "size_mismatch"
                audit.size_mismatches += 1
            else:
                result.ok = True
                audit.present_files += 1
                audit.present_bytes += actual_size
        audit.results.append(result)

    return audit


def audit_disk(disk_path: str, dist_image: str,
               products: list[str] | None = None) -> AuditReport:
    """Audit every (or a specific subset of) installed products on disk."""
    if products is None:
        products = _list_installed_products(disk_path)

    report = AuditReport(disk=disk_path, dist_image=dist_image)
    for p in products:
        a = audit_product(disk_path, dist_image, p)
        if a is None:
            # No .idb found for this product in the dist image — skip
            # (could mean it's a different dist or third-party package).
            continue
        report.products.append(a)
    return report


# ── CLI ─────────────────────────────────────────────────────────────────


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit installed IRIX system against package .idb manifests.")
    ap.add_argument("--disk", required=True,
                    help="installed system disk image (qcow2 or raw)")
    ap.add_argument("--dist-image", required=True,
                    help="combined dist EFS image with the .idb manifests")
    ap.add_argument("--product", action="append",
                    help="restrict to one product (repeat for multiple)")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--missing-only", action="store_true",
                    help="show only products with missing files")
    args = ap.parse_args(argv)

    products = args.product if args.product else None
    print(f"Auditing {args.disk} against {args.dist_image}", file=sys.stderr)
    if products:
        print(f"  products: {', '.join(products)}", file=sys.stderr)

    report = audit_disk(args.disk, args.dist_image, products=products)

    # JSON output
    if args.json:
        data = {
            "disk": report.disk,
            "dist_image": report.dist_image,
            "summary": report.summary(),
            "products": [
                {
                    "product": a.product,
                    "expected_files": a.expected_files,
                    "expected_bytes": a.expected_bytes,
                    "present_files": a.present_files,
                    "present_bytes": a.present_bytes,
                    "missing_files": a.missing_files,
                    "size_mismatches": a.size_mismatches,
                    "type_mismatches": a.type_mismatches,
                    "coverage_pct": round(a.coverage_pct, 2),
                    "is_complete": a.is_complete,
                    "results": [
                        {"path": r.path, "expected_size": r.expected_size,
                         "actual_size": r.actual_size, "reason": r.reason,
                         "ok": r.ok}
                        for r in a.results
                    ],
                }
                for a in report.products
            ],
        }
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"wrote {args.json}", file=sys.stderr)

    # Text report
    print()
    print(f"{'product':<30} {'files':>8} {'present':>8} {'missing':>8} "
          f"{'size!':>6} {'cov':>6}  status")
    print("-" * 80)
    for a in sorted(report.products, key=lambda p: p.product):
        if args.missing_only and a.is_complete:
            continue
        status = "OK" if a.is_complete else ("EMPTY" if a.present_files == 0
                                              else "PARTIAL")
        print(f"{a.product:<30} {a.expected_files:>8} {a.present_files:>8} "
              f"{a.missing_files:>8} {a.size_mismatches:>6} "
              f"{a.coverage_pct:>5.1f}%  {status}")
    print("-" * 80)
    print(report.summary())

    # Non-zero exit if any product is partial/empty
    bad = sum(1 for a in report.products if not a.is_complete)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
