#!/usr/bin/env python3
"""Combine IRIX dist/ directories into a single EFS disk image.

Merges extracted CD dist/ directories into a single mountable SGI disk
image. IRIX inst can then see ALL packages simultaneously, resolving
cross-CD dependency issues that cause 47+ package skips in sequential
CD-by-CD installation.

Two layouts are supported:
  - Single-dist (default): all files deduped into one dist/ directory.
  - Per-CD (per_cd_layout=True): each CD gets its own subdirectory.
    inst opens each subdirectory as a separate distribution and handles
    dependency/conflict resolution itself. No dedup needed.

The output image has:
  - SGI volume header at sector 0 (with valid partition table)
  - EFS filesystem starting at sector 64 (partition 7, type=7)

Usage:
    python3 -m pyirix.dist.combine build                # Build 6.5 image
    python3 -m pyirix.dist.combine --suite mipspro build # Build MIPSPro image
    python3 -m pyirix.dist.combine verify               # List contents
    python3 -m pyirix.dist.combine check                # Dry-run

    # Discovery mode: point at any extraction dir, auto-find dist content
    python3 -m pyirix.dist.combine --source /tmp/extracted --version 6.5 build
    python3 -m pyirix.dist.combine --source /tmp/extracted -o combo.img build
"""

import argparse
import io
import os
import re
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTRACT_BASE = PROJECT_ROOT / "software_library" / "extraced_irix_cds"
OUTPUT_IMAGE = PROJECT_ROOT / "software_library" / "irix65_combined_dist.img"

# Explicit list of IRIX 6.5.22 CDs — all sources for a maximalist install.
# Per-CD layout: each CD gets its own subdirectory on the EFS image so inst
# can see both base and overlay versions of every product simultaneously.
IRIX65_CDS = [
    "6.5-foundation-1",
    "6.5-foundation-2",
    "6.5-development-libraries_812-0766-003",
    "ONC3_NFS_812-0774-002",
    "irix-6.5.22-overlay-1",
    "irix-6.5.22-overlay-2",
    "irix-6.5.22-overlay-3",
    "6.5-applications-2004",
]

COMBO_DIR = "prepackaged_combo_discs"

# ── Version/suite configurations ────────────────────────────────────
#
# Each config specifies:
#   cds:          list of CD directory names under extract_base
#   output:       output image path relative to software_library/
#   extract_base: base directory containing the CD directories
#   dist_subdir:  if True, files are in cd_dir/dist/ not cd_dir/ directly
#   dist_override: dict mapping cd_name -> preferred dist subdir name
#                  (e.g., "dist6.5" instead of "dist" for version-specific packages)

CONFIGS = {
    "6.5": {
        # All 6.5.22 CDs + Development Libraries + ONC3/NFS in per-CD layout.
        # inst opens each subdirectory as a separate distribution and resolves
        # base+overlay dependencies automatically — no dedup, no conflicts.
        "cds": IRIX65_CDS,
        "output": str(PROJECT_ROOT / "software_library" / COMBO_DIR
                       / "IRIX_6.5.22_combined_dist.img"),
        "extract_base": PROJECT_ROOT / "software_library" / "extraced_irix_cds",
        "dist_subdir": "auto",
        "per_cd_layout": True,
        # ONC3/NFS CD has version-specific dist dirs (dist6.3, dist6.4, dist6.5)
        "dist_override": {
            "ONC3_NFS_812-0774-002": "dist6.5",
        },
    },
    "6.5.5": {
        "cds": [
            "6.5-foundation-1",
            "6.5-foundation-2",
            "6.5.5_install-tools-overlays-1_812-0818-005",
            "6.5.5_overlays-2_812-0819-005",
            "6.5.5_applications_812-0877-004",
        ],
        "output": str(PROJECT_ROOT / "software_library" / COMBO_DIR
                       / "IRIX_6.5.5_Foundation_and_Overlays_combined_dist.img"),
        "extract_base": PROJECT_ROOT / "software_library" / "extraced_irix_cds",
        "dist_subdir": "auto",  # Auto-detect: use dist/ if it exists, else flat
    },
    "mipspro": {
        # MIPSPro + base OS + overlays: all CDs loaded simultaneously.
        # Each CD's dist files go into a separate subdirectory on the EFS
        # image. inst opens each subdirectory as a separate distribution
        # and handles dependency/conflict resolution itself — no dedup needed.
        "cds": [
            "ONC3_NFS_812-0774-002",
            "alldev/developmentlibraries",
            "alldev/prodev",
            "alldev/MIPSPro7.4.4",
            "6.5-foundation-1",
            "6.5-foundation-2",
            "6.5.5_install-tools-overlays-1_812-0818-005",
            "6.5.5_overlays-2_812-0819-005",
            "6.5.5_applications_812-0877-004",
        ],
        "output": str(PROJECT_ROOT / "software_library" / COMBO_DIR
                       / "MIPSpro_7.4_and_Development_Libraries_combined_dist.img"),
        "extract_base": PROJECT_ROOT / "software_library" / "extraced_irix_cds",
        "dist_subdir": "auto",
        "per_cd_layout": True,  # Each CD gets its own subdirectory (no dedup)
    },
    "devtools-655": {
        # Dev tools for 6.5.5: base MIPSpro 7.4 + 7.4.4 overlays + dev libs + ProDev.
        # Includes 6.5.5 overlays CD 2 (not CD 1!) — that's where dev_655m,
        # irix_dev_655m, x_dev_655m, gl_dev_655m etc. live, resolving version
        # incompatibility between foundation-era dev libs and 6.5.5 eoe.sw.base.
        # Per-CD layout so inst can resolve base+overlay dependencies itself.
        "cds": [
            "alldev/MIPSPro7.4.4",
            "alldev/developmentlibraries",
            "alldev/prodev",
            "6.5.5_overlays-2_812-0819-005",
        ],
        "output": str(PROJECT_ROOT / "software_library" / COMBO_DIR
                       / "devtools_for_655_with_base.img"),
        "extract_base": PROJECT_ROOT / "software_library" / "extraced_irix_cds",
        "dist_subdir": "auto",
        "per_cd_layout": True,
    },
    "apps-655": {
        # IRIX 6.5.5 Applications CD + overlays for version compatibility.
        # Includes desktop_eoe, desktop_tools, sysadmdesktop, and all standard
        # IRIX applications (nedit, netscape, demos, insight, etc.).
        # Overlays CD 2 has desktop_eoe_655m, desktop_tools_655m, etc.
        "cds": [
            "6.5.5_applications_812-0877-004",
            "6.5.5_overlays-2_812-0819-005",
        ],
        "output": str(PROJECT_ROOT / "software_library" / COMBO_DIR
                       / "irix655_applications.img"),
        "extract_base": PROJECT_ROOT / "software_library" / "extraced_irix_cds",
        "dist_subdir": "auto",
        "per_cd_layout": True,
    },
}


def discover_config_from_catalog(version, categories=None):
    """Auto-build a combine_dist config from image_catalog discovery.

    Scans software_library/ for disc images matching the version, then
    checks if they have extracted CD directories. Returns a config dict
    compatible with CONFIGS or None if no extracted CDs are found.

    This is a convenience function for the --discover CLI mode.
    """
    try:
        from pyirix_qemu.catalog.images import scan_software_library, CATEGORY_OS_BASE, \
            CATEGORY_OS_OVERLAY, CATEGORY_DEV_COMPILER, CATEGORY_DEV_TOOLS, \
            CATEGORY_APPLICATIONS, CATEGORY_DEMOS, CATEGORY_NETWORKING
    except ImportError:
        return None

    if categories is None:
        categories = [
            CATEGORY_OS_BASE, CATEGORY_OS_OVERLAY, CATEGORY_DEV_COMPILER,
            CATEGORY_DEV_TOOLS, CATEGORY_APPLICATIONS, CATEGORY_DEMOS,
            CATEGORY_NETWORKING,
        ]

    catalog = scan_software_library()
    images = catalog.get_install_set(version, categories)

    if not images:
        return None

    # For each discovered image, check if there's an extracted CD directory
    # in extraced_irix_cds/. We can't use raw .img files directly in
    # combine_dist — it needs extracted dist/ directories.
    extract_base = PROJECT_ROOT / "software_library" / "extraced_irix_cds"
    if not extract_base.exists():
        return None

    # Use the existing discover_dist_entries to find what's extracted
    entries, _ = discover_dist_entries(extract_base, version_filter=version)
    if not entries:
        return None

    cd_names = [name for name, _ in entries]

    safe_ver = version.replace(".", "_")
    output_name = f"IRIX_{safe_ver}_discovered_combined_dist.img"
    output_path = str(PROJECT_ROOT / "software_library" / COMBO_DIR / output_name)

    return {
        "cds": cd_names,
        "output": output_path,
        "extract_base": extract_base,
        "dist_subdir": "auto",
        "per_cd_layout": True,
        "_discovered": True,
        "_source_images": [img.display_name for img in images],
    }


# ── Discovery-based dist finding ────────────────────────────────────

def discover_dist_entries(extract_base, version_filter=None):
    """Discover dist locations by scanning for .idb files.

    Walks an extraction directory, finds every directory containing .idb
    files, applies version filtering and dedup, and returns a list of
    (short_name, abs_path) pairs suitable for collect_dist_files_per_cd().

    Dedup rules:
      1. If cd_root/ has .idb AND cd_root/dist/ has .idb, prefer dist/
      2. If cd/dist6.X/ and cd/dist/dist6.X/ both exist with same files,
         keep nested, drop root-level
      3. Sibling superset: within the same CD, if one dist location's .idb
         filenames are a strict superset of another sibling's, keep only
         the superset (handles unified dist/ vs per-component sub-CDs)
    """
    extract_base = Path(extract_base)
    if not extract_base.exists():
        return []

    # Pass 1: find all directories containing .idb files
    raw = []
    for root, dirs, files in os.walk(extract_base):
        idb_files = [f for f in files if f.endswith('.idb')]
        if not idb_files:
            continue
        root_path = Path(root)
        try:
            rel = root_path.relative_to(extract_base)
        except ValueError:
            continue
        parts = rel.parts
        if not parts:
            continue
        cd_name = parts[0]
        raw.append((cd_name, root_path, set(f for f in idb_files)))

    # Pass 2: version filtering — drop dist6.X where X doesn't match
    excluded_versions = set()
    if version_filter:
        filtered = []
        for cd_name, path, idbs in raw:
            m = re.match(r'^dist(\d+\.\d+)$', path.name)
            if m and not version_filter.startswith(m.group(1)):
                excluded_versions.add(path.name)
                continue
            filtered.append((cd_name, path, idbs))
        raw = filtered

    # Pass 3: dedup — root vs dist/ child
    deduped = {}
    dist_child_set = set()
    for cd_name, path, idbs in raw:
        rel = path.relative_to(extract_base)
        if len(rel.parts) >= 2 and rel.parts[1] == 'dist':
            dist_child_set.add(cd_name)
    for cd_name, path, idbs in raw:
        rel = path.relative_to(extract_base)
        # Skip CD root if it also has a dist/ child with .idb files
        if len(rel.parts) == 1 and cd_name in dist_child_set:
            continue
        deduped[path] = (cd_name, path, idbs)

    # Pass 4: dedup — cd/dist6.X/ vs cd/dist/dist6.X/
    to_remove = set()
    for path in list(deduped):
        rel = path.relative_to(extract_base)
        parts = rel.parts
        if len(parts) == 2 and re.match(r'^dist\d', parts[1]):
            nested = extract_base / parts[0] / 'dist' / parts[1]
            if nested in deduped:
                root_files = set(f.name for f in path.iterdir()
                                 if f.is_file())
                nested_files = set(f.name for f in nested.iterdir()
                                   if f.is_file())
                if root_files <= nested_files:
                    to_remove.add(path)
    for p in to_remove:
        del deduped[p]

    # Pass 5: drop all-symlink dist directories
    # Some CDs (e.g., MIPSpro 7.4.4 combo ISO) create a unified dist/
    # directory containing symlinks to per-component sub-CDs. These
    # convenience directories would create broken symlinks on the EFS
    # image. Drop any directory where ALL .idb files are symlinks.
    to_remove = set()
    for path in deduped:
        idb_paths = list(path.glob('*.idb'))
        if idb_paths and all(p.is_symlink() for p in idb_paths):
            to_remove.add(path)

    for p in to_remove:
        del deduped[p]

    # Build (short_name, path) pairs with readable names
    results = []
    for path in sorted(deduped):
        cd_name, _, idbs = deduped[path]
        rel = path.relative_to(extract_base)
        # Build short name: drop 'dist' components, join with '_'
        meaningful = [p for p in rel.parts if p != 'dist']
        if not meaningful:
            meaningful = [rel.parts[0]]
        short_name = '_'.join(meaningful)
        results.append((short_name, path))

    return results, excluded_versions


# ── EFS / SGI-volume-header builder ──────────────────────────────────
# Moved to pyirix.efs.builder (first-class pyirix.efs capability). Re-export
# the full public API so existing combine.py code keeps working unchanged.
from pyirix.efs.builder import *  # noqa: F401,F403
from pyirix.efs.builder import (  # explicit: names used directly below
    EFSImageBuilder, build_volume_header, pack_extent, build_dir_blocks,
    pack_inode, pack_superblock,
    VHMAGIC, NVDIR, NPARTAB, SECTOR_SIZE, VH_SIZE,
    PTYPE_VOLHDR, PTYPE_SYSV, PTYPE_VOLUME, PTYPE_EFS,
    EFS_MAGIC, EFS_BLOCK_SIZE, EFS_INOPBB, EFS_INODE_SIZE, EFS_ROOT_INODE,
    EFS_MAX_EXTENTS, EFS_MAX_EXTENT_LENGTH, EFS_DIRBLK_MAGIC,
    S_IFMT, S_IFDIR, S_IFREG, S_IFLNK, EFS_PARTITION_START,
)
def find_dist_dirs(config=None):
    """Find dist directories for the given configuration.

    Handles two extraction formats:
    - Flat: files directly in cd_dir/ (6.5 staging, path_filter stripped dist/)
    - Subdirectory: files in cd_dir/dist/ (6.5.5 and dev CDs, full extraction)

    When dist_subdir="auto", auto-detects: uses dist/ if it exists, else flat.
    When dist_override is set for a CD, uses that subdirectory name instead.
    """
    if config is None:
        # Legacy path: use original 6.5 defaults
        config = CONFIGS.get("6.5", {
            "cds": IRIX65_CDS,
            "extract_base": EXTRACT_BASE,
            "dist_subdir": False,
        })

    extract_base = Path(config["extract_base"])
    cd_list = config["cds"]
    dist_subdir = config.get("dist_subdir", False)
    dist_override = config.get("dist_override", {})

    results = []
    if not extract_base.exists():
        return results

    for cd_name in cd_list:
        cd_dir = extract_base / cd_name
        if not cd_dir.exists() or not cd_dir.is_dir():
            continue

        # Determine the actual directory containing dist files
        override = dist_override.get(cd_name)
        if override:
            # Explicit override (e.g., "dist6.5" for All-Compiler CD)
            target = cd_dir / override
            if target.exists() and target.is_dir():
                results.append((cd_name, target))
            else:
                # Fall back to dist/ if override doesn't exist
                fallback = cd_dir / "dist"
                if fallback.exists() and fallback.is_dir():
                    results.append((cd_name, fallback))
        elif dist_subdir == "auto":
            # Auto-detect: use dist/ if it exists and has files, else flat
            dist_dir = cd_dir / "dist"
            if dist_dir.exists() and dist_dir.is_dir() and \
               any(dist_dir.iterdir()):
                results.append((cd_name, dist_dir))
            else:
                results.append((cd_name, cd_dir))
        elif dist_subdir:
            # Files are in dist/ subdirectory
            dist_dir = cd_dir / "dist"
            if dist_dir.exists() and dist_dir.is_dir():
                results.append((cd_name, dist_dir))
        else:
            # Files are flat in cd_dir
            results.append((cd_name, cd_dir))

    return results


def extract_dist_from_image(image_path, output_dir):
    """Extract dist/ files from an EFS .img to a host directory.

    Walks the EFS filesystem recursively, finds all files in dist/
    (including nested subdirs like dist6.5/), and writes them flat
    into output_dir/ preserving only the filename (not subdirectory
    structure). Later extractions overwrite earlier ones for dedup.

    Returns count of files extracted.
    """
    from pyirix.efs.reader import (find_efs_partition, read_superblock,
                                    read_inode, read_dir_entries,
                                    read_file_data, EFS_ROOT_INODE,
                                    S_IFDIR, S_IFREG, S_IFMT)

    os.makedirs(output_dir, exist_ok=True)
    count = 0

    with open(image_path, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print(f"  No EFS partition in {image_path}", file=sys.stderr)
            return 0

        part_offset, part_size = result
        sb = read_superblock(f, part_offset)
        if not sb:
            print(f"  Invalid EFS superblock in {image_path}",
                  file=sys.stderr)
            return 0

        root_inode = read_inode(f, part_offset, sb, EFS_ROOT_INODE)
        if not root_inode:
            return 0

        def walk_and_extract(dir_ino, path, in_dist):
            """Recursively walk directories, extracting files under dist/."""
            nonlocal count
            inode = read_inode(f, part_offset, sb, dir_ino)
            if not inode or (inode['mode'] & S_IFMT) != S_IFDIR:
                return

            entries = read_dir_entries(f, part_offset, sb, inode)
            for entry_name, ino in entries:
                if entry_name.startswith('.'):
                    continue

                child_inode = read_inode(f, part_offset, sb, ino)
                if not child_inode:
                    continue

                ftype = child_inode['mode'] & S_IFMT
                child_path = path + '/' + entry_name if path else entry_name

                if ftype == S_IFDIR:
                    # Enter dist directories (dist, dist6.5, dist6.3, etc.)
                    child_in_dist = in_dist or entry_name.startswith('dist')
                    walk_and_extract(ino, child_path, child_in_dist)

                elif ftype == S_IFREG and in_dist:
                    # Extract regular files found under dist/
                    try:
                        data = read_file_data(f, part_offset, sb,
                                              child_inode)
                        out_path = os.path.join(output_dir, entry_name)
                        with open(out_path, 'wb') as out:
                            out.write(data)
                        count += 1
                    except Exception as e:
                        print(f"  WARNING: failed to extract "
                              f"{child_path}: {e}", file=sys.stderr)

        walk_and_extract(EFS_ROOT_INODE, '', False)

    return count


def collect_dist_files(dist_dirs):
    """Collect all files from all dist/ directories.

    Returns:
        files: list of (relative_path, host_path, is_symlink, symlink_target)
        total_size: total bytes of file data
        conflicts: list of (filename, [sources])
    """
    file_map = {}   # filename -> (host_path, source_cd)
    conflicts = defaultdict(list)
    files = []
    total_size = 0

    for cd_name, dist_dir in dist_dirs:
        for item in sorted(dist_dir.iterdir()):
            try:
                if not item.exists() and not item.is_symlink():
                    continue
            except PermissionError:
                continue

            name = item.name

            # Skip .redirect (causes inst to look for dist6.5/ subdir)
            # and other dotfiles that confuse multi-CD combined images
            if name == '.redirect':
                continue

            if name in file_map:
                # Record conflict
                prev_cd = file_map[name][1]
                if len(conflicts[name]) == 0:
                    conflicts[name].append(prev_cd)
                conflicts[name].append(cd_name)
                # Keep the later one (overlays supersede foundation)
                file_map[name] = (item, cd_name)
            else:
                file_map[name] = (item, cd_name)

    for name, (host_path, _) in sorted(file_map.items()):
        rel_path = f"dist/{name}"
        try:
            if host_path.is_symlink():
                target = os.readlink(host_path)
                files.append((rel_path, host_path, True, target))
            elif host_path.is_file():
                size = host_path.stat().st_size
                files.append((rel_path, host_path, False, ''))
                total_size += size
        except PermissionError:
            print(f"  WARNING: permission denied on {host_path}, skipping",
                  file=sys.stderr)
            continue

    return files, total_size, dict(conflicts)


def collect_dist_files_per_cd(dist_dirs):
    """Collect dist files organized by CD, no dedup.

    Each CD's files go into a subdirectory named after the CD.
    Returns:
        cd_files: list of (dir_name, [(rel_path, host_path, is_symlink, target)])
        total_size: total bytes
    """
    cd_files = []
    total_size = 0

    for cd_name, dist_dir in dist_dirs:
        # Use leaf of CD path as directory name
        # e.g. "alldev/MIPSPro7.4.4" -> "MIPSPro7.4.4"
        dir_name = os.path.basename(cd_name)
        files = []

        for item in sorted(dist_dir.iterdir()):
            name = item.name
            if name == '.redirect' or name.startswith('.'):
                continue
            rel_path = f"{dir_name}/{name}"
            try:
                if item.is_symlink():
                    target = os.readlink(item)
                    files.append((rel_path, item, True, target))
                elif item.is_file():
                    size = item.stat().st_size
                    files.append((rel_path, item, False, ''))
                    total_size += size
            except PermissionError:
                continue

        if files:
            cd_files.append((dir_name, files))

    return cd_files, total_size


# ── CLI commands ────────────────────────────────────────────────────

def _get_config(args):
    """Resolve the configuration from CLI args.

    Priority: --suite selects by name, --version selects if it matches a
    config key, falling back to "6.5" for backward compatibility.
    Not used when --source is provided (discovery mode).
    """
    suite = getattr(args, 'suite', None)
    version = getattr(args, 'version', None)

    if suite:
        key = suite
    elif version and version in CONFIGS:
        key = version
    else:
        key = "6.5"

    if key not in CONFIGS:
        print(f"Unknown config: {key!r}. Available: {', '.join(CONFIGS)}",
              file=sys.stderr)
        return None

    config = CONFIGS[key]

    # Allow CLI --output to override config output path
    output = getattr(args, 'output', None)
    if output:
        config = dict(config)
        config["output"] = output

    return config


def cmd_build(args):
    """Build the combined EFS disk image."""
    source_dir = getattr(args, 'source', None)

    if source_dir:
        # Discovery mode: scan --source dir for .idb files
        extract_base = Path(source_dir)
        if not extract_base.exists():
            print(f"Source directory not found: {source_dir}",
                  file=sys.stderr)
            return 1

        version_filter = getattr(args, 'version', None)
        entries, excluded = discover_dist_entries(
            extract_base, version_filter=version_filter)

        if not entries:
            print(f"No dist content found under {extract_base} "
                  f"(no directories with .idb files)", file=sys.stderr)
            return 1

        dist_dirs = entries  # list of (short_name, abs_path)
        output_path = getattr(args, 'output', None) or str(OUTPUT_IMAGE)
        use_per_cd = True  # discovery mode always uses per-CD layout

        print(f"Building combined distribution image (discovery mode)")
        print(f"  Source: {extract_base}")
        if version_filter:
            print(f"  Version filter: {version_filter}")
        if excluded:
            print(f"  Excluded: {', '.join(sorted(excluded))}")
        print(f"  Output: {output_path}")
        print(f"  Dist locations: {len(dist_dirs)}")
        for short_name, dist_path in dist_dirs:
            idb_count = sum(1 for f in dist_path.iterdir()
                            if f.name.endswith('.idb'))
            file_count_d = sum(1 for f in dist_path.iterdir()
                               if f.is_file())
            print(f"    {short_name:45s} {idb_count:3d} idb  "
                  f"{file_count_d} files")
        print()

    else:
        # Config mode: use CONFIGS dict
        config = _get_config(args)
        if config is None:
            return 1

        dist_dirs = find_dist_dirs(config)
        extract_base = Path(config["extract_base"])
        output_path = config["output"]

        if not dist_dirs:
            print(f"No extracted dist directories found under "
                  f"{extract_base}", file=sys.stderr)
            print("Run: python3 tools/extract_all_cds.py",
                  file=sys.stderr)
            return 1

        # Pre-flight version conflict analysis
        try:
            from pyirix.dist.pkg_analyzer import run_preflight
            run_preflight(dist_dirs)
        except ImportError:
            pass

        print(f"Building combined distribution image")
        print(f"  Source: {extract_base}")
        print(f"  Output: {output_path}")
        print(f"  CDs found: {len(dist_dirs)}")
        for cd_name, dist_dir in dist_dirs:
            try:
                count = sum(1 for f in dist_dir.iterdir()
                            if f.is_file())
            except PermissionError:
                count = sum(1 for f in dist_dir.iterdir())
            print(f"    {cd_name}: {count} files")
        print()

        use_per_cd = config.get("per_cd_layout", False)

    if use_per_cd:
        print("Collecting dist files (per-CD layout)...")
        cd_files, total_size = collect_dist_files_per_cd(dist_dirs)
        file_count = sum(len(files) for _, files in cd_files)
        print(f"  Total files: {file_count} across {len(cd_files)} CD directories")
        print(f"  Total size: {total_size // (1024*1024)}MB")
        for dir_name, files in cd_files:
            print(f"    {dir_name}: {len(files)} files")
    else:
        print("Collecting dist files...")
        files, total_size, conflicts = collect_dist_files(dist_dirs)
        file_count = len(files)
        print(f"  Total files: {file_count}")
        print(f"  Total size: {total_size // (1024*1024)}MB")
        if conflicts:
            print(f"  Filename overlaps: {len(conflicts)} "
                  f"(later CDs take priority)")
            if args.verbose:
                for name, sources in sorted(conflicts.items()):
                    print(f"    {name}: {', '.join(sources)}")

    # Run inst conflict simulation (informational only)
    try:
        from pyirix.dist.pkg_analyzer import InstSimulator
        print("\nSimulating inst conflicts for target 'indy'...")
        sim = InstSimulator("indy")
        for cd_name, dist_dir in dist_dirs:
            sim.load_dist(dist_dir)
        result = sim.simulate()

        print(f"  Products: {result.total_products}, "
              f"Subsystems: {result.selected_subsystems} selected, "
              f"{result.hw_excluded_subsystems} hw-excluded")
        if result.install_size:
            print(f"  Install size: ~{result.install_size / (1024*1024):.0f} MB")

        if result.conflicts:
            print(f"  Predicted conflicts: {len(result.conflicts)}")
            by_type = {}
            for c in result.conflicts:
                by_type.setdefault(c.conflict_type, []).append(c)
            for ctype, clist in sorted(by_type.items()):
                print(f"    {ctype}: {len(clist)}")
                for c in clist[:5]:
                    print(f"      {c.detail}")
                if len(clist) > 5:
                    print(f"      ... and {len(clist) - 5} more")
        else:
            print("  No conflicts predicted.")
        print()
    except (ImportError, Exception):
        pass  # irix_pkg_analyzer not available or simulation failed

    # Calculate image size: data + overhead
    # Add 20% overhead for filesystem structures
    efs_bytes = int(total_size * 1.2) + 64 * 1024 * 1024  # +64MB for metadata
    efs_blocks = efs_bytes // EFS_BLOCK_SIZE

    # Total disk = EFS partition start + EFS blocks
    total_sectors = EFS_PARTITION_START + efs_blocks
    total_mb = total_sectors * SECTOR_SIZE // (1024 * 1024)
    print(f"  Image size: {total_mb}MB")

    # Build EFS filesystem
    print("\nBuilding EFS filesystem...")
    builder = EFSImageBuilder(efs_blocks)

    symlink_count = 0
    if use_per_cd:
        # Per-CD layout: each CD gets its own subdirectory
        added = 0
        for dir_name, files in cd_files:
            builder.add_directory(dir_name)
            for rel_path, host_path, is_symlink, target in files:
                if is_symlink:
                    builder.add_symlink(rel_path, target)
                    symlink_count += 1
                else:
                    with open(host_path, 'rb') as f:
                        data = f.read()
                    builder.add_file(rel_path, data)
                added += 1
                if added % 50 == 0:
                    print(f"\r  Added {added}/{file_count} files...",
                          end='', flush=True)
        print(f"\r  Added {added}/{file_count} files.   ")
    else:
        # Single-dist layout: all files under dist/
        builder.add_directory("dist")
        for i, (rel_path, host_path, is_symlink, target) in enumerate(files):
            if is_symlink:
                builder.add_symlink(rel_path, target)
                symlink_count += 1
            else:
                with open(host_path, 'rb') as f:
                    data = f.read()
                builder.add_file(rel_path, data)
            if (i + 1) % 50 == 0 or i == len(files) - 1:
                print(f"\r  Added {i+1}/{len(files)} files...", end='',
                      flush=True)
        print()

    if symlink_count:
        print(f"  Symlinks: {symlink_count}")

    # Build EFS image to temp location, then prepend volume header
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.efs') as tmp:
        tmp_path = tmp.name

    try:
        builder.build(tmp_path)

        # Now create the final image: VH + EFS
        print(f"\nBuilding final disk image with volume header...")
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        # Use actual EFS fs_size (= firstcg + cgfsize * ncg)
        actual_total = EFS_PARTITION_START + builder.fs_size

        with open(output_path, 'wb') as out:
            # Write volume header at sector 0
            vh = build_volume_header(actual_total, EFS_PARTITION_START)
            out.write(vh)

            # Pad to partition start
            pad_bytes = EFS_PARTITION_START * SECTOR_SIZE - VH_SIZE
            out.write(b'\x00' * pad_bytes)

            # Copy EFS data
            with open(tmp_path, 'rb') as efs_in:
                while True:
                    chunk = efs_in.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)

        final_size = os.path.getsize(output_path)
        print(f"\nCombined image created: {output_path}")
        print(f"  Size: {final_size // (1024*1024)}MB")
        print(f"  Files: {file_count} ({symlink_count} symlinks)")
        print(f"  EFS partition: sector {EFS_PARTITION_START}")

    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return 0


def cmd_check(args):
    """Dry-run: check for conflicts without building."""
    source_dir = getattr(args, 'source', None)

    if source_dir:
        extract_base = Path(source_dir)
        if not extract_base.exists():
            print(f"Source directory not found: {source_dir}",
                  file=sys.stderr)
            return 1
        version_filter = getattr(args, 'version', None)
        entries, excluded = discover_dist_entries(
            extract_base, version_filter=version_filter)
        if not entries:
            print(f"No dist content found under {extract_base}",
                  file=sys.stderr)
            return 1
        dist_dirs = entries

        print(f"Checking {len(dist_dirs)} dist locations "
              f"(discovery mode)...\n")
        if excluded:
            print(f"  Excluded: {', '.join(sorted(excluded))}")
    else:
        config = _get_config(args)
        if config is None:
            return 1
        dist_dirs = find_dist_dirs(config)
        extract_base = Path(config["extract_base"])
        if not dist_dirs:
            print(f"No extracted dist directories found under "
                  f"{extract_base}", file=sys.stderr)
            return 1
        print(f"Checking {len(dist_dirs)} CDs for conflicts...\n")

        # Pre-flight version conflict analysis
        try:
            from pyirix.dist.pkg_analyzer import run_preflight
            run_preflight(dist_dirs)
        except ImportError:
            pass

    # Per-CD collection for size estimation
    cd_files, total_size = collect_dist_files_per_cd(dist_dirs)
    file_count = sum(len(files) for _, files in cd_files)
    print(f"Total dist files: {file_count}")
    print(f"Total size: {total_size // (1024*1024)}MB")
    print(f"Estimated image size: "
          f"{int(total_size * 1.2) // (1024*1024) + 64}MB")

    for dir_name, files in cd_files:
        size = sum(f[1].stat().st_size for f in files
                   if not f[2])  # non-symlinks
        print(f"  {dir_name:45s} {len(files):4d} files  "
              f"{size // (1024*1024):5d}MB")

    return 0


def cmd_verify(args):
    """Verify the combined image using efs_reader."""
    config = _get_config(args)
    if config is None:
        return 1
    image_path = config["output"]
    if not os.path.exists(image_path):
        print(f"Image not found: {image_path}", file=sys.stderr)
        print("Run: python3 -m pyirix.dist.combine build", file=sys.stderr)
        return 1

    print(f"Verifying: {image_path}")
    print(f"  Size: {os.path.getsize(image_path) // (1024*1024)}MB\n")

    # Use efs_reader to verify
    from pyirix.efs.reader import (find_efs_partition, read_superblock,
                                    count_files, EFS_ROOT_INODE)

    with open(image_path, 'rb') as f:
        result = find_efs_partition(f)
        if not result:
            print("ERROR: No EFS partition found!", file=sys.stderr)
            return 1

        part_offset, part_size = result
        print(f"EFS partition at offset {part_offset} "
              f"({part_offset // 1024}KB)")

        sb = read_superblock(f, part_offset)
        if not sb:
            print("ERROR: Invalid EFS superblock!", file=sys.stderr)
            return 1

        print(f"  Magic: 0x{sb['fs_magic']:06x}")
        print(f"  Size: {sb['fs_size']} blocks "
              f"({sb['fs_size'] * EFS_BLOCK_SIZE // (1024*1024)}MB)")
        print(f"  CGs: {sb['fs_ncg']}, "
              f"size {sb['fs_cgfsize']}")
        print(f"  Free blocks: {sb['fs_tfree']}")
        print(f"  Free inodes: {sb['fs_tinode']}")

        files, dirs, symlinks, total = count_files(
            f, part_offset, sb, EFS_ROOT_INODE, '/')
        print(f"\n  Files: {files}")
        print(f"  Dirs: {dirs}")
        print(f"  Symlinks: {symlinks}")
        print(f"  Total data: {total // (1024*1024)}MB")

        if files > 0:
            print("\nImage appears valid.")
        else:
            print("\nWARNING: No files found — image may be corrupt.")
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Combine IRIX dist directories into single EFS image"
    )
    parser.add_argument('--output', '-o', default=None,
                        help=f'Output image path (default: config-specific)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--source', metavar='DIR',
                        help='Extraction directory to scan for dist content '
                             '(discovers by .idb files, bypasses CONFIGS)')
    parser.add_argument('--version', metavar='VER',
                        help='IRIX version filter (e.g. 6.5) — excludes '
                             'non-matching dist6.X dirs. Also selects config '
                             'when not using --source.')
    parser.add_argument('--suite',
                        help=f'Software suite config ({", ".join(k for k in CONFIGS if "." not in k)})')

    parser.add_argument('--discover', action='store_true',
                        help='Auto-discover CDs from image_catalog instead of '
                             'using hardcoded CONFIGS. Requires --version.')

    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.add_parser('build', help='Build combined image')
    subparsers.add_parser('check',
                          help='Dry-run: check for conflicts')
    subparsers.add_parser('verify',
                          help='Verify built image with efs_reader')

    args = parser.parse_args()

    # Handle --discover mode: auto-build config from image_catalog
    if getattr(args, 'discover', False):
        ver = args.version
        if not ver:
            print("Error: --discover requires --version", file=sys.stderr)
            return 1
        discovered_cfg = discover_config_from_catalog(ver)
        if not discovered_cfg:
            print(f"Error: no extracted CDs found for version {ver}",
                  file=sys.stderr)
            return 1
        # Register as a runtime config
        key = f"discovered-{ver}"
        CONFIGS[key] = discovered_cfg
        args.suite = key
        if not args.version:
            args.version = ver
        print(f"Discovered {len(discovered_cfg['cds'])} CD directories "
              f"for IRIX {ver}")

    commands = {
        'build': cmd_build,
        'check': cmd_check,
        'verify': cmd_verify,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)

