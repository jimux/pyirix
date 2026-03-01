#!/usr/bin/env python3
"""Extract a set of IRIX CD images into software_library/extraced_irix_cds/.

Handles EFS disk images, tar.gz archives, and nested tar archives.
Each CD gets its own directory with dist/ preserved as a subdirectory
for use by dist_analyzer.py.

Usage:
    python3 -m pyirix.efs.extract              # Extract all CDs
    python3 -m pyirix.efs.extract --check      # Show status without extracting
    python3 -m pyirix.efs.extract --force       # Re-extract even if done
    python3 -m pyirix.efs.extract --only 3,7    # Extract specific entries by number
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from pyirix.efs.reader import (
    find_efs_partition, read_superblock, read_inode, read_dir_entries,
    extract_recursive, EFS_ROOT_INODE, S_IFMT, S_IFDIR,
)

SOFTWARE_LIB = PROJECT_ROOT / "software_library"
EXTRACT_BASE = SOFTWARE_LIB / "extraced_irix_cds"

# ── CD Manifest ──────────────────────────────────────────────────────
# Each entry: source path (relative to software_library/), target dir name,
# format type, and human-readable label.
#
# Format types:
#   efs           - Standard EFS image; extract full root → gets dist/ naturally
#   efs_install   - EFS image with install/ instead of dist/; remap to dist/
#   tar.gz        - Gzipped tar with dist/ at top level
#   tar_nested    - Tar with one level of nesting to strip

MANIFEST = [
    # ── IRIX 6.5.5 Base + Applications (5 EFS images) ────────────────
    {
        "num": 1,
        "source": "irix_6.5.5_images/IRIX 6.5 Applications August 1999 - 812-0877-004.efs.img",
        "target": "6.5.5_applications_812-0877-004",
        "format": "efs",
        "label": "IRIX 6.5 Applications Aug 1999",
    },
    {
        "num": 2,
        "source": "irix_6.5.5_images/IRIX 6.5.5 Installation Tools and Overlays (1 of 2) - 812-0818-005.efs.img",
        "target": "6.5.5_install-tools-overlays-1_812-0818-005",
        "format": "efs",
        "label": "IRIX 6.5.5 Install Tools & Overlays 1/2",
    },
    {
        "num": 3,
        "source": "irix_6.5.5_images/IRIX 6.5.5 Overlays (2 of 2) - 812-0819-005.efs.img",
        "target": "6.5.5_overlays-2_812-0819-005",
        "format": "efs",
        "label": "IRIX 6.5.5 Overlays 2/2",
    },
    {
        "num": 4,
        "source": "IRIX 6.5 Foundation 1.img",
        "target": "6.5-foundation-1",
        "format": "efs",
        "label": "IRIX 6.5 Foundation 1",
    },
    {
        "num": 5,
        "source": "IRIX 6.5 Foundation 2.img",
        "target": "6.5-foundation-2",
        "format": "efs",
        "label": "IRIX 6.5 Foundation 2",
    },
    # ── Networking (1 EFS image) ──────────────────────────────────────
    {
        "num": 6,
        "source": "ONC3 NFS Version 3 for IRIX 6.2, 6.3, 6.4, and 6.5 - 812-0774-002.efs.img",
        "target": "ONC3_NFS_812-0774-002",
        "format": "efs",
        "label": "ONC3/NFS 3",
    },
    # ── MIPSpro Compilers (4 images, mixed formats) ───────────────────
    {
        "num": 7,
        "source": "dev CDs/mipspro/MIPSpro_All-Compiler_CD_May_1999_for_IRIX_6.5_and_later-812-0925-001.tar.gz",
        "target": "mipspro_all_compiler_812-0925-001",
        "format": "tar.gz",
        "label": "MIPSpro All-Compiler 7.3",
    },
    {
        "num": 8,
        "source": "dev CDs/mipspro/MIPSPro_7.4_C_Compiler.tar",
        "target": "mipspro_74_c_compiler",
        "format": "tar_nested",
        "strip": 1,
        "label": "MIPSpro C 7.4 (tar)",
    },
    {
        "num": 9,
        "source": "dev CDs/mipspro/MIPSpro C++ Compiler 7.4 - 812-0400-010.efs.img",
        "target": "mipspro_cpp_74_812-0400-010",
        "format": "efs",
        "label": "MIPSpro C++ 7.4",
    },
    {
        "num": 10,
        "source": "dev CDs/mipspro/MIPSpro C Compiler 7.4 - 812-0707-010.efs.img",
        "target": "mipspro_c_74_812-0707-010",
        "format": "efs",
        "label": "MIPSpro C 7.4 (standalone)",
    },
    # ── Dev Tools (4 images) ──────────────────────────────────────────
    {
        "num": 11,
        "source": "dev CDs/prodev/ProDev Developers Suite - 812-0768-003.efs.img",
        "target": "prodev_suite_812-0768-003",
        "format": "efs",
        "label": "ProDev Suite",
    },
    {
        "num": 12,
        "source": "dev CDs/prodev/ProDev WorkShop 2.9.3 - 812-0768-007.efs.img",
        "target": "prodev_workshop_293_812-0768-007",
        "format": "efs",
        "label": "ProDev WorkShop 2.9.3",
    },
    {
        "num": 13,
        "source": "dev CDs/IRIX Development Foundation 1.3.iso",
        "target": "dev_foundation_13_812-0757-004",
        "format": "efs",
        "label": "Dev Foundation 1.3",
    },
    {
        "num": 14,
        "source": "dev CDs/development_libraries/IRIX 6.5 Development Libraries February 2002 - 812-0766-003.efs.img",
        "target": "dev_libraries_812-0766-003",
        "format": "efs",
        "label": "Dev Libraries Feb 2002",
    },
    # ── Demos (2 EFS images) ─────────────────────────────────────────
    {
        "num": 15,
        "source": "demo_cds/O2 Demos 1.3 for IRIX 6.5 - 812-0780-002.efs.img",
        "target": "o2_demos_812-0780-002",
        "format": "efs_install",
        "label": "O2 Demos 1.3",
    },
    {
        "num": 16,
        "source": "demo_cds/SGI Impact Demos CD 6.2-812-0527-001.efs.img",
        "target": "impact_demos_812-0527-001",
        "format": "efs",
        "label": "Impact Demos 6.2",
    },
]


def is_extracted(target_dir):
    """Check if a CD has already been extracted (dist/ exists with files)."""
    dist_dir = target_dir / "dist"
    if not dist_dir.exists():
        return False
    files = [f for f in dist_dir.iterdir() if f.is_file()]
    return len(files) >= 3


def extract_efs(source_path, target_dir):
    """Extract a full EFS filesystem into target_dir."""
    with open(source_path, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print(f"  ERROR: No EFS partition found in {source_path.name}")
            return False

        part_offset, part_size = result
        sb = read_superblock(f, part_offset)
        if not sb:
            print(f"  ERROR: Invalid EFS superblock in {source_path.name}")
            return False

        target_dir.mkdir(parents=True, exist_ok=True)
        stats = extract_recursive(f, part_offset, sb, EFS_ROOT_INODE,
                                  '/', str(target_dir))
        print(f"  Extracted: {stats['files']} files, {stats['dirs']} dirs, "
              f"{stats['symlinks']} symlinks", end="")
        if stats['errors']:
            print(f", {stats['errors']} errors", end="")
        print()
        return stats['errors'] == 0


def extract_efs_install_as_dist(source_path, target_dir):
    """Extract EFS install/ directory contents as dist/.

    Some CDs (like O2 Demos) use install/ instead of dist/ for
    their distribution packages. We extract install/ and place
    the contents under dist/ so dist_analyzer.py can find them.
    """
    with open(source_path, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print(f"  ERROR: No EFS partition found in {source_path.name}")
            return False

        part_offset, part_size = result
        sb = read_superblock(f, part_offset)
        if not sb:
            print(f"  ERROR: Invalid EFS superblock in {source_path.name}")
            return False

        # Extract install/ contents into target_dir/dist/
        # path_filter="install" strips the install/ prefix
        dist_dest = target_dir / "dist"
        dist_dest.mkdir(parents=True, exist_ok=True)
        stats = extract_recursive(f, part_offset, sb, EFS_ROOT_INODE,
                                  '/', str(dist_dest), path_filter="install")
        print(f"  Extracted install/ as dist/: {stats['files']} files, "
              f"{stats['dirs']} dirs", end="")
        if stats['errors']:
            print(f", {stats['errors']} errors", end="")
        print()
        return stats['errors'] == 0


def extract_tar_gz(source_path, target_dir):
    """Extract a gzipped tar archive into target_dir."""
    target_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["tar", "xzf", str(source_path), "-C", str(target_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR: tar extraction failed: {result.stderr.strip()}")
        return False

    # Count extracted files
    dist_dir = target_dir / "dist"
    if dist_dir.exists():
        count = sum(1 for _ in dist_dir.iterdir())
        print(f"  Extracted: {count} items in dist/")
    else:
        count = sum(1 for _ in target_dir.iterdir())
        print(f"  Extracted: {count} items (no dist/ found)")
    return True


def extract_tar_nested(source_path, target_dir, strip=1):
    """Extract a tar archive with --strip-components to remove nesting."""
    target_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["tar", "xf", str(source_path), "-C", str(target_dir),
         f"--strip-components={strip}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR: tar extraction failed: {result.stderr.strip()}")
        return False

    dist_dir = target_dir / "dist"
    if dist_dir.exists():
        count = sum(1 for _ in dist_dir.iterdir())
        print(f"  Extracted (strip={strip}): {count} items in dist/")
    else:
        count = sum(1 for _ in target_dir.iterdir())
        print(f"  Extracted (strip={strip}): {count} items (no dist/ found)")
    return True


def extract_entry(entry, force=False):
    """Extract a single manifest entry."""
    source_path = SOFTWARE_LIB / entry["source"]
    target_dir = EXTRACT_BASE / entry["target"]

    print(f"\n[{entry['num']:2d}] {entry['label']}")
    print(f"  Source: {entry['source']}")
    print(f"  Target: {entry['target']}/")

    if not source_path.exists():
        print(f"  SKIP: Source image not found")
        return False

    if not force and is_extracted(target_dir):
        dist_files = sum(1 for f in (target_dir / "dist").iterdir()
                         if f.is_file())
        print(f"  SKIP: Already extracted ({dist_files} files in dist/)")
        return True

    fmt = entry["format"]
    if fmt == "efs":
        return extract_efs(source_path, target_dir)
    elif fmt == "efs_install":
        return extract_efs_install_as_dist(source_path, target_dir)
    elif fmt == "tar.gz":
        return extract_tar_gz(source_path, target_dir)
    elif fmt == "tar_nested":
        strip = entry.get("strip", 1)
        return extract_tar_nested(source_path, target_dir, strip)
    else:
        print(f"  ERROR: Unknown format '{fmt}'")
        return False


def cmd_check():
    """Show extraction status for all CDs (dry run)."""
    print(f"IRIX CD Extraction Status")
    print(f"Base: {EXTRACT_BASE}\n")

    ok = 0
    missing = 0
    for entry in MANIFEST:
        source_path = SOFTWARE_LIB / entry["source"]
        target_dir = EXTRACT_BASE / entry["target"]
        src_exists = source_path.exists()

        if is_extracted(target_dir):
            dist_files = sum(1 for f in (target_dir / "dist").iterdir()
                             if f.is_file())
            status = f"OK ({dist_files} dist files)"
            ok += 1
        elif not src_exists:
            status = "NO SOURCE"
            missing += 1
        else:
            size_mb = source_path.stat().st_size // (1024 * 1024)
            status = f"NEEDS EXTRACTION ({size_mb}MB)"
            missing += 1

        print(f"  [{entry['num']:2d}] {status:30s}  {entry['label']}")

    print(f"\n{ok} extracted, {missing} remaining")
    return 0 if missing == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="Extract IRIX CD images for dist analysis"
    )
    parser.add_argument('--check', action='store_true',
                        help='Show status without extracting')
    parser.add_argument('--force', action='store_true',
                        help='Re-extract even if already done')
    parser.add_argument('--only', type=str, default=None,
                        help='Comma-separated list of entry numbers to extract')
    args = parser.parse_args()

    if args.check:
        return cmd_check()

    # Parse --only filter
    only_nums = None
    if args.only:
        only_nums = set(int(n) for n in args.only.split(','))

    EXTRACT_BASE.mkdir(parents=True, exist_ok=True)

    print(f"Extracting IRIX CDs to {EXTRACT_BASE}")
    print(f"{'='*60}")

    success = 0
    failed = 0
    skipped = 0

    for entry in MANIFEST:
        if only_nums and entry["num"] not in only_nums:
            continue

        result = extract_entry(entry, force=args.force)
        if result is True:
            if not args.force and is_extracted(EXTRACT_BASE / entry["target"]):
                skipped += 1
            else:
                success += 1
        elif result is False:
            failed += 1

    print(f"\n{'='*60}")
    print(f"Done: {success} extracted, {skipped} skipped, {failed} failed")

    if failed:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
