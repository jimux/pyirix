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


# ── SGI Volume Header constants ──────────────────────────────────────

VHMAGIC = 0x0BE5A941
NVDIR = 15
NPARTAB = 16
SECTOR_SIZE = 512
VH_SIZE = 512

PTYPE_VOLHDR = 0
PTYPE_SYSV = 5
PTYPE_VOLUME = 6
PTYPE_EFS = 7

# ── EFS constants ────────────────────────────────────────────────────

EFS_MAGIC = 0x072959
EFS_BLOCK_SIZE = 512
EFS_INOPBB = 4             # inodes per basic block
EFS_INODE_SIZE = 128
EFS_ROOT_INODE = 2
EFS_MAX_EXTENTS = 12
EFS_MAX_EXTENT_LENGTH = 248
EFS_DIRBLK_MAGIC = 0xBEEF

# File types
S_IFMT  = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

# EFS partition starts at this sector in the disk image
EFS_PARTITION_START = 64  # 32KB offset


# ── Correct SGI EFS Extent Format ────────────────────────────────────

def pack_extent(magic, bn, length, offset):
    """Pack an EFS extent into 8 bytes (correct SGI format).

    On-disk layout:
      word1 = (ex_magic << 24) | (ex_bn & 0xFFFFFF)
      word2 = (ex_length << 24) | (ex_offset & 0xFFFFFF)
    """
    word1 = ((magic & 0xFF) << 24) | (bn & 0xFFFFFF)
    word2 = ((length & 0xFF) << 24) | (offset & 0xFFFFFF)
    return struct.pack('>II', word1, word2)


# ── Correct 0xBEEF Directory Block Builder ───────────────────────────

def build_dir_blocks(entries):
    """Build 0xBEEF directory blocks from list of (name, inode) tuples.

    Entries are packed into 512-byte blocks using the SGI slot-based format:
      [0:2]  magic = 0xBEEF
      [2]    firstused (minimum valid slot offset / 2)
      [3]    slots (number of entries)
      [4:4+slots]  slot table (each byte = entry_byte_offset / 2)
      entries packed after slot table

    Each entry: 4 bytes inode (BE) + 1 byte namelen + name bytes
    Entry size: 5 + namelen, no padding needed

    Returns bytes (multiple of 512).
    """
    blocks = []

    # Split entries across blocks as needed
    remaining = list(entries)

    while remaining:
        block = bytearray(EFS_BLOCK_SIZE)
        # Reserve header: magic(2) + firstused(1) + slots(1)
        header_size = 4
        # We'll fill the slot table as we add entries

        slot_table = []
        entry_data_parts = []
        # entries start right after header + slot table
        # But we don't know slot table size until we know how many entries fit
        # So iterate: try to fit entries, expanding slot table as needed

        entries_in_block = []
        for e in remaining:
            name_bytes = e[0].encode('ascii', errors='replace')
            entry_size = 5 + len(name_bytes)  # 4(ino) + 1(namelen) + name
            entries_in_block.append((e, name_bytes, entry_size))

        # Figure out how many entries fit by simulating the actual packing.
        # The packing layout is:
        #   [0:4]  header (magic, firstused, slots)
        #   [4:4+N] slot table (N = number of entries)
        #   [data_start:] entries, each at even-aligned offsets
        # data_start = 4 + N, rounded up to even.
        # Each entry: 4(ino) + 1(namelen) + name, starting at even offset.
        fitted = []
        for i, (e, name_bytes, entry_size) in enumerate(entries_in_block):
            n = i + 1  # number of entries if we include this one
            data_start = header_size + n
            if data_start % 2 != 0:
                data_start += 1
            # Simulate packing all fitted entries + this new one
            offset = data_start
            for _, prev_nb, prev_es in fitted:
                if offset % 2 != 0:
                    offset += 1
                offset += prev_es
            # Now check if the new entry fits
            if offset % 2 != 0:
                offset += 1
            if offset + entry_size > EFS_BLOCK_SIZE:
                break
            fitted.append((e, name_bytes, entry_size))

        if not fitted:
            # Entry too large for a block (shouldn't happen with 255-char names)
            remaining.pop(0)
            continue

        # Build the block
        num_entries = len(fitted)
        slot_table_start = 4
        data_start = slot_table_start + num_entries

        # Align data_start to even boundary for slot offset encoding
        if data_start % 2 != 0:
            data_start += 1

        # Pack entries sequentially starting at data_start
        # Each entry must be at an even offset (slot_val = offset / 2)
        current_offset = data_start
        slot_values = []
        for e, name_bytes, entry_size in fitted:
            name, ino = e
            # Align to even boundary
            if current_offset % 2 != 0:
                current_offset += 1
            # Write entry at current_offset
            struct.pack_into('>I', block, current_offset, ino)
            block[current_offset + 4] = len(name_bytes)
            block[current_offset + 5:current_offset + 5 + len(name_bytes)] = name_bytes
            slot_values.append(current_offset // 2)
            current_offset += entry_size

        # Write header
        struct.pack_into('>H', block, 0, EFS_DIRBLK_MAGIC)
        min_slot = min(slot_values) if slot_values else 0
        block[2] = min_slot  # firstused
        block[3] = num_entries  # slots

        # Write slot table
        for i, sv in enumerate(slot_values):
            block[slot_table_start + i] = sv

        blocks.append(bytes(block))
        remaining = remaining[len(fitted):]

    if not blocks:
        # Empty directory — still need at least one block
        block = bytearray(EFS_BLOCK_SIZE)
        struct.pack_into('>H', block, 0, EFS_DIRBLK_MAGIC)
        block[2] = 0
        block[3] = 0
        blocks.append(bytes(block))

    return b''.join(blocks)


# ── EFS Inode ────────────────────────────────────────────────────────

def pack_inode(mode, nlink, uid, gid, size, mtime, numextents, extents_data):
    """Pack a 128-byte EFS inode.

    extents_data: raw bytes of packed extents (up to 12 * 8 = 96 bytes)
    """
    buf = bytearray(EFS_INODE_SIZE)
    struct.pack_into('>H', buf, 0, mode)
    struct.pack_into('>h', buf, 2, nlink)
    struct.pack_into('>H', buf, 4, uid)
    struct.pack_into('>H', buf, 6, gid)
    struct.pack_into('>i', buf, 8, size)
    struct.pack_into('>i', buf, 12, mtime)   # atime
    struct.pack_into('>i', buf, 16, mtime)   # mtime
    struct.pack_into('>i', buf, 20, mtime)   # ctime
    struct.pack_into('>I', buf, 24, 1)       # gen
    struct.pack_into('>h', buf, 28, numextents)
    buf[30] = 0  # version
    buf[31] = 0  # spare

    # Copy extent data (up to 96 bytes at offset 32)
    ext_len = min(len(extents_data), 96)
    buf[32:32 + ext_len] = extents_data[:ext_len]

    return bytes(buf)


# ── EFS Superblock ───────────────────────────────────────────────────

def pack_superblock(fs_size, firstcg, cgfsize, cgisize, ncg,
                    bmsize, tfree, tinode, bmblock, replsb):
    """Pack a 512-byte EFS superblock."""
    buf = bytearray(EFS_BLOCK_SIZE)
    now = int(time.time())

    struct.pack_into('>i', buf, 0, fs_size)
    struct.pack_into('>i', buf, 4, firstcg)
    struct.pack_into('>i', buf, 8, cgfsize)
    struct.pack_into('>h', buf, 12, cgisize)     # inode BLOCKS per CG
    struct.pack_into('>h', buf, 14, 16)          # sectors per track
    struct.pack_into('>h', buf, 16, 16)          # heads
    struct.pack_into('>h', buf, 18, ncg)
    struct.pack_into('>h', buf, 20, 0)           # dirty
    struct.pack_into('>h', buf, 22, 0)           # padding
    struct.pack_into('>i', buf, 24, now)         # time
    struct.pack_into('>I', buf, 28, EFS_MAGIC)   # magic (unsigned)
    buf[32:38] = b'irix\x00\x00'                 # fname
    buf[38:44] = b'dist\x00\x00'                 # fpack
    struct.pack_into('>i', buf, 44, bmsize)
    struct.pack_into('>i', buf, 48, tfree)
    struct.pack_into('>i', buf, 52, tinode)
    struct.pack_into('>i', buf, 56, bmblock)
    struct.pack_into('>i', buf, 60, replsb)

    # EFS superblock checksum (from IRIX kernel source efs_vfsops.c):
    #   checksum = 0;
    #   sp = (ushort *)fs;
    #   while (sp < (ushort *)&fs->fs_checksum) {
    #       checksum ^= *sp++;
    #       checksum = (checksum << 1) | (checksum < 0);
    #   }
    # This is XOR of big-endian 16-bit words with left rotation,
    # over bytes 0..87 (fs_checksum is at offset 88).

    # Zero the checksum field first
    struct.pack_into('>i', buf, 88, 0)

    # XOR + rotate-left over 16-bit words up to fs_checksum (offset 88)
    checksum = 0
    for i in range(0, 88, 2):
        word = struct.unpack('>H', buf[i:i+2])[0]
        checksum ^= word
        # Rotate left: shift left 1, carry sign bit to bit 0
        # "checksum < 0" in C (signed 32-bit) means bit 31 is set
        sign = 1 if (checksum & 0x80000000) else 0
        checksum = ((checksum << 1) | sign) & 0xFFFFFFFF

    # Store as 32-bit (use unsigned pack to avoid sign issues)
    struct.pack_into('>I', buf, 88, checksum & 0xFFFFFFFF)

    return bytes(buf)


# ── SGI Volume Header ───────────────────────────────────────────────

def build_volume_header(total_sectors, efs_start_sector):
    """Build a 512-byte SGI volume header with partition table."""
    data = bytearray(VH_SIZE)

    # Magic
    struct.pack_into('>I', data, 0, VHMAGIC)
    # rootpt=0, swappt=1
    struct.pack_into('>h', data, 4, 0)
    struct.pack_into('>h', data, 6, 1)
    # bootfile (empty)

    # Device parameters at offset 24, 48 bytes
    dp_offset = 24
    struct.pack_into('>H', data, dp_offset + 16, SECTOR_SIZE)  # dp_secbytes

    # Volume directory at offset 72 (24 + 48)
    vd_offset = 72
    # Entry 0: sgilabel
    name = b'sgilabel'
    data[vd_offset:vd_offset + len(name)] = name
    struct.pack_into('>ii', data, vd_offset + 8, 0, VH_SIZE)

    # Partition table at offset 312 (72 + 15*16)
    pt_offset = vd_offset + NVDIR * 16

    # Partition 7: EFS filesystem
    pt7_off = pt_offset + 7 * 12
    efs_nblks = total_sectors - efs_start_sector
    struct.pack_into('>iii', data, pt7_off,
                     efs_nblks, efs_start_sector, PTYPE_EFS)

    # Partition 8: volume header
    pt8_off = pt_offset + 8 * 12
    struct.pack_into('>iii', data, pt8_off,
                     efs_start_sector, 0, PTYPE_VOLHDR)

    # Partition 10: entire volume
    pt10_off = pt_offset + 10 * 12
    struct.pack_into('>iii', data, pt10_off,
                     total_sectors, 0, PTYPE_VOLUME)

    # Checksum at offset 504 (312 + 16*12)
    csum_offset = pt_offset + NPARTAB * 12
    struct.pack_into('>i', data, csum_offset, 0)

    # Sum all 32-bit words
    total = 0
    for i in range(0, VH_SIZE, 4):
        total = (total + struct.unpack('>I', data[i:i+4])[0]) & 0xFFFFFFFF

    csum = (-total) & 0xFFFFFFFF
    if csum >= 0x80000000:
        csum_signed = csum - 0x100000000
    else:
        csum_signed = csum
    struct.pack_into('>i', data, csum_offset, csum_signed)

    return bytes(data)


# ── EFS Filesystem Builder ──────────────────────────────────────────

class EFSImageBuilder:
    """Builds a correct SGI EFS filesystem image from files.

    Uses the correct on-disk formats:
    - Extent: word1 = (magic<<24)|bn, word2 = (length<<24)|offset
    - Directory: 0xBEEF slot-based blocks
    - Superblock cgisize = inode BLOCKS per CG (not total inodes)
    """

    def __init__(self, total_blocks):
        self.total_blocks = total_blocks
        self.files = {}       # path -> (mode, size, data_or_target)
        self.dirs = {}        # path -> list of child names
        self.next_inode = EFS_ROOT_INODE + 1

        # Geometry (computed later)
        self.cgisize = 0      # inode blocks per CG
        self.cgfsize = 0      # total blocks per CG
        self.firstcg = 0      # first CG block
        self.ncg = 0          # number of CGs
        self.bitmap_blocks = 0
        self.bitmap_start = 2

        # Block allocation
        self.next_data_block = 0

        # Inode assignments
        self.path_to_inode = {}

        # Root
        self.dirs['/'] = []
        self.path_to_inode['/'] = EFS_ROOT_INODE

    def add_file(self, path, data, mode=S_IFREG | 0o644,
                 link_target=''):
        """Add a regular file or symlink."""
        path = '/' + path.lstrip('/')
        self._ensure_parents(path)
        self.files[path] = (mode, len(data), data, link_target)

        # Assign inode
        self.path_to_inode[path] = self.next_inode
        self.next_inode += 1

        # Add to parent's child list
        parent = os.path.dirname(path) or '/'
        name = os.path.basename(path)
        if name not in self.dirs.get(parent, []):
            self.dirs.setdefault(parent, []).append(name)

    def add_symlink(self, path, target):
        """Add a symbolic link."""
        target_bytes = target.encode('ascii', errors='replace')
        self.add_file(path, target_bytes, mode=S_IFLNK | 0o777,
                      link_target=target)

    def add_directory(self, path, mode=S_IFDIR | 0o755):
        """Add a directory."""
        path = '/' + path.strip('/')
        if path == '/':
            return
        self._ensure_parents(path)
        if path not in self.dirs:
            self.dirs[path] = []
            self.path_to_inode[path] = self.next_inode
            self.next_inode += 1

            parent = os.path.dirname(path) or '/'
            name = os.path.basename(path)
            if name not in self.dirs.get(parent, []):
                self.dirs.setdefault(parent, []).append(name)

    def _ensure_parents(self, path):
        """Create parent directories if they don't exist."""
        parts = path.strip('/').split('/')
        for i in range(len(parts) - 1):
            p = '/' + '/'.join(parts[:i+1])
            if p not in self.dirs:
                self.add_directory(p)

    def _compute_geometry(self):
        """Compute filesystem geometry."""
        total_items = len(self.files) + len(self.dirs)
        needed_inodes = total_items + 128  # slack

        # Inode blocks per CG: 8 blocks = 32 inodes per CG
        self.cgisize = 8
        inodes_per_cg = self.cgisize * EFS_INOPBB

        # Number of CGs
        self.ncg = max(1, (needed_inodes + inodes_per_cg - 1) // inodes_per_cg)

        # Bitmap
        bitmap_bits = self.total_blocks
        bitmap_bytes = (bitmap_bits + 7) // 8
        self.bitmap_blocks = (bitmap_bytes + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
        self.bitmap_start = 2

        # First CG after boot + superblock + bitmap
        self.firstcg = 2 + self.bitmap_blocks

        # CG size: inode blocks + data blocks
        # Distribute remaining blocks evenly across CGs
        remaining = self.total_blocks - self.firstcg
        self.cgfsize = remaining // self.ncg

        # Ensure cgfsize > cgisize
        if self.cgfsize <= self.cgisize:
            self.cgfsize = self.cgisize + 16

        # fs_size must exactly equal firstcg + cgfsize * ncg (EFS_MAGIC rule)
        self.fs_size = self.firstcg + self.cgfsize * self.ncg

    def _inode_to_bb(self, ino):
        """Convert inode number to basic block number."""
        ipcg = self.cgisize * EFS_INOPBB
        cg = ino // ipcg
        cgbb = (ino >> 2) % self.cgisize
        return self.firstcg + cg * self.cgfsize + cgbb

    def _allocate_blocks(self, num_blocks):
        """Allocate contiguous blocks, return list of (bn, length, offset).

        Allocates data blocks linearly across CGs, skipping the inode
        blocks at the start of each CG.
        """
        if num_blocks == 0:
            return []

        extents = []
        remaining = num_blocks
        logical_offset = 0

        while remaining > 0:
            # Check if we've hit the inode area of the next CG
            cg_of_block = (self.next_data_block - self.firstcg) // self.cgfsize
            cg_start = self.firstcg + cg_of_block * self.cgfsize
            cg_data_start = cg_start + self.cgisize
            cg_data_end = cg_start + self.cgfsize

            # If we're in the inode area, skip to data area
            if self.next_data_block < cg_data_start:
                self.next_data_block = cg_data_start

            # If we're past this CG, move to next CG's data area
            if self.next_data_block >= cg_data_end:
                next_cg = cg_of_block + 1
                if next_cg >= self.ncg:
                    raise RuntimeError(
                        f"EFS filesystem full: need {remaining} more blocks, "
                        f"no CGs left")
                self.next_data_block = self.firstcg + next_cg * self.cgfsize + self.cgisize

            # Recalculate how much space is left in this CG
            cg_of_block = (self.next_data_block - self.firstcg) // self.cgfsize
            cg_data_end = self.firstcg + cg_of_block * self.cgfsize + self.cgfsize
            available = cg_data_end - self.next_data_block

            length = min(remaining, EFS_MAX_EXTENT_LENGTH, available)
            bn = self.next_data_block
            extents.append((bn, length, logical_offset))
            self.next_data_block += length
            remaining -= length
            logical_offset += length

        return extents

    # Max blocks per indirect extent (from IRIX kernel efs_ino.h)
    EFS_MAXINDIRBBS = 64

    def _allocate_indirect_blocks(self, num_blocks):
        """Allocate blocks for indirect extent table.

        Like _allocate_blocks but limits each run to EFS_MAXINDIRBBS (64)
        instead of EFS_MAX_EXTENT_LENGTH (248). Returns list of (bn, length, offset).
        """
        if num_blocks == 0:
            return []

        extents = []
        remaining = num_blocks
        logical_offset = 0

        while remaining > 0:
            cg_of_block = (self.next_data_block - self.firstcg) // self.cgfsize
            cg_start = self.firstcg + cg_of_block * self.cgfsize
            cg_data_start = cg_start + self.cgisize
            cg_data_end = cg_start + self.cgfsize

            if self.next_data_block < cg_data_start:
                self.next_data_block = cg_data_start
            if self.next_data_block >= cg_data_end:
                next_cg = cg_of_block + 1
                if next_cg >= self.ncg:
                    raise RuntimeError(
                        f"EFS filesystem full: need {remaining} more blocks")
                self.next_data_block = (self.firstcg + next_cg * self.cgfsize
                                        + self.cgisize)

            cg_of_block = (self.next_data_block - self.firstcg) // self.cgfsize
            cg_data_end = (self.firstcg + cg_of_block * self.cgfsize
                           + self.cgfsize)
            available = cg_data_end - self.next_data_block

            # Limit to EFS_MAXINDIRBBS per run
            length = min(remaining, self.EFS_MAXINDIRBBS, available)
            bn = self.next_data_block
            extents.append((bn, length, logical_offset))
            self.next_data_block += length
            remaining -= length
            logical_offset += length

        return extents

    def _build_indirect_extents(self, data_extents):
        """Handle files with more than 12 direct extents using indirect mode.

        When numextents > EFS_DIRECTEXTENTS (12):
        - Allocate blocks to hold the data extent descriptors
        - Pack data extents into those blocks (64 per block)
        - Create indirect extents pointing to those blocks
        - inode stores indirect extents; extents[0].ex_offset = num_indirect
        - numextents remains the total count of DATA extents

        Returns (numextents, inode_ext_bytes, indirect_data_blocks)
        where indirect_data_blocks are (bn, bytes) tuples to write.
        """
        num_data_extents = len(data_extents)

        # Pack all data extents into a byte buffer
        ext_table = b''
        for bn, length, offset in data_extents:
            ext_table += pack_extent(0, bn, length, offset)

        # How many blocks needed to store the extent table?
        # Each block holds 512/8 = 64 extent descriptors
        EXTENTS_PER_BLOCK = EFS_BLOCK_SIZE // 8
        indirect_blocks_needed = ((num_data_extents + EXTENTS_PER_BLOCK - 1)
                                  // EXTENTS_PER_BLOCK)

        # Allocate blocks for the extent table with 64-block-per-run limit
        indirect_extents = self._allocate_indirect_blocks(indirect_blocks_needed)

        if len(indirect_extents) > EFS_MAX_EXTENTS:
            raise RuntimeError(
                f"File needs {len(indirect_extents)} indirect extents "
                f"(max {EFS_MAX_EXTENTS}). "
                f"Total data extents: {num_data_extents}, "
                f"indirect blocks: {indirect_blocks_needed}")

        # Build indirect data blocks (the extent table stored on disk)
        indirect_data_blocks = []
        table_offset = 0
        for ibn, ilength, _ in indirect_extents:
            chunk_size = ilength * EFS_BLOCK_SIZE
            chunk = ext_table[table_offset:table_offset + chunk_size]
            # Pad to full block(s)
            if len(chunk) < chunk_size:
                chunk = chunk + b'\x00' * (chunk_size - len(chunk))
            indirect_data_blocks.append((ibn, chunk))
            table_offset += chunk_size

        # Build the inode extent data: indirect extents
        # extents[0].ex_offset = number of indirect extents
        num_indirect = len(indirect_extents)
        inode_ext_bytes = b''
        for i, (ibn, ilength, _) in enumerate(indirect_extents):
            if i == 0:
                # First indirect extent: ex_offset = num_indirect
                inode_ext_bytes += pack_extent(0, ibn, ilength, num_indirect)
            else:
                # Subsequent: ex_offset = 0 (unused for indirect)
                inode_ext_bytes += pack_extent(0, ibn, ilength, 0)

        return num_data_extents, inode_ext_bytes, indirect_data_blocks

    def build(self, output_path):
        """Build the complete EFS image and write to file."""
        self._compute_geometry()
        total_items = len(self.files) + len(self.dirs)

        print(f"  EFS geometry:")
        print(f"    fs_size: {self.fs_size} blocks "
              f"({self.fs_size * EFS_BLOCK_SIZE // (1024*1024)}MB)")
        print(f"    firstcg: {self.firstcg}")
        print(f"    Cylinder groups: {self.ncg}")
        print(f"    CG size: {self.cgfsize} blocks")
        print(f"    Inode blocks/CG: {self.cgisize} "
              f"({self.cgisize * EFS_INOPBB} inodes/CG)")
        print(f"    Items: {total_items} "
              f"({len(self.dirs)} dirs, {len(self.files)} files)")
        print(f"    Verify: firstcg + cgfsize*ncg = "
              f"{self.firstcg} + {self.cgfsize}*{self.ncg} = "
              f"{self.firstcg + self.cgfsize * self.ncg} == fs_size={self.fs_size}")

        # Data blocks start after inode blocks in first CG
        self.next_data_block = self.firstcg + self.cgisize

        # Build all inode and data content
        # inode_num -> (inode_bytes, [(data_block, data_bytes), ...])
        inode_table = {}

        # Process directories
        now = int(time.time())
        for path in sorted(self.dirs.keys()):
            ino = self.path_to_inode[path]
            children = self.dirs[path]

            # Build directory entries: (name, inode)
            dir_entries = []
            # . and ..
            parent_path = os.path.dirname(path.rstrip('/')) or '/'
            parent_ino = self.path_to_inode.get(parent_path, EFS_ROOT_INODE)
            dir_entries.append(('.', ino))
            dir_entries.append(('..', parent_ino))

            for child_name in sorted(children):
                if path == '/':
                    child_path = '/' + child_name
                else:
                    child_path = path + '/' + child_name
                child_ino = self.path_to_inode.get(child_path)
                if child_ino is not None:
                    dir_entries.append((child_name, child_ino))

            # Build directory block data
            dir_data = build_dir_blocks(dir_entries)
            dir_blocks_needed = len(dir_data) // EFS_BLOCK_SIZE

            # Allocate blocks for directory data
            extents = self._allocate_blocks(dir_blocks_needed)

            # Pack extents
            ext_bytes = b''
            for bn, length, offset in extents:
                ext_bytes += pack_extent(0, bn, length, offset)

            nlink = 2 + sum(1 for c in children
                            if ('/' + c if path == '/' else path + '/' + c)
                            in self.dirs)

            inode_bytes = pack_inode(
                mode=S_IFDIR | 0o755,
                nlink=nlink,
                uid=0, gid=0,
                size=len(dir_data),
                mtime=now,
                numextents=len(extents),
                extents_data=ext_bytes,
            )

            data_blocks = []
            offset_in_data = 0
            for bn, length, _ in extents:
                chunk = dir_data[offset_in_data:offset_in_data + length * EFS_BLOCK_SIZE]
                data_blocks.append((bn, chunk))
                offset_in_data += length * EFS_BLOCK_SIZE

            inode_table[ino] = (inode_bytes, data_blocks)

        # Process files
        indirect_count = 0
        for path in sorted(self.files.keys()):
            ino = self.path_to_inode[path]
            mode, size, data, link_target = self.files[path]

            if mode & S_IFMT == S_IFLNK:
                file_data = link_target.encode('ascii', errors='replace')
                file_size = len(file_data)
            else:
                file_data = data
                file_size = size

            if file_size > 0:
                blocks_needed = (file_size + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
                extents = self._allocate_blocks(blocks_needed)
            else:
                extents = []

            if len(extents) <= EFS_MAX_EXTENTS:
                # Direct extents — fit in the inode
                ext_bytes = b''
                for bn, length, offset in extents:
                    ext_bytes += pack_extent(0, bn, length, offset)
                numextents = len(extents)
                extra_data_blocks = []
            else:
                # Indirect extents — need extent table blocks
                numextents, ext_bytes, extra_data_blocks = \
                    self._build_indirect_extents(extents)
                indirect_count += 1

            inode_bytes = pack_inode(
                mode=mode,
                nlink=1,
                uid=0, gid=0,
                size=file_size,
                mtime=now,
                numextents=numextents,
                extents_data=ext_bytes,
            )

            data_blocks = []
            offset_in_data = 0
            for bn, length, _ in extents:
                end = offset_in_data + length * EFS_BLOCK_SIZE
                chunk = file_data[offset_in_data:end]
                # Pad to full extent
                if len(chunk) < length * EFS_BLOCK_SIZE:
                    chunk = chunk + b'\x00' * (length * EFS_BLOCK_SIZE - len(chunk))
                data_blocks.append((bn, chunk))
                offset_in_data = end

            # Add indirect extent table blocks (if any)
            data_blocks.extend(extra_data_blocks)

            inode_table[ino] = (inode_bytes, data_blocks)

        if indirect_count:
            print(f"  Files with indirect extents: {indirect_count}")

        # Now write the image
        print(f"  Writing image to {output_path}...")

        with open(output_path, 'wb') as f:
            # Block 0: boot block (empty)
            f.write(b'\x00' * EFS_BLOCK_SIZE)

            # Block 1: superblock (placeholder, rewrite later)
            sb_offset = EFS_BLOCK_SIZE
            f.write(b'\x00' * EFS_BLOCK_SIZE)

            # Blocks 2-N: bitmap (placeholder)
            f.write(b'\x00' * (self.bitmap_blocks * EFS_BLOCK_SIZE))

            # Write inodes into their CG positions
            for ino, (inode_bytes, _) in inode_table.items():
                bb = self._inode_to_bb(ino)
                slot = ino & 0x3
                file_offset = bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE
                f.seek(file_offset)
                f.write(inode_bytes)

            # Write data blocks
            for ino, (_, data_blocks) in inode_table.items():
                for bn, chunk in data_blocks:
                    f.seek(bn * EFS_BLOCK_SIZE)
                    f.write(chunk)

            # Compute free blocks/inodes
            total_inodes = self.ncg * self.cgisize * EFS_INOPBB
            free_inodes = total_inodes - len(inode_table)

            # Build bitmap: EFS bitmap has 1=free, 0=allocated
            # Start with all free, then mark allocated blocks
            bm_bytes = (self.fs_size + 7) // 8
            bitmap = bytearray(b'\xff' * bm_bytes)

            def mark_allocated(block_num):
                if 0 <= block_num < self.fs_size:
                    bitmap[block_num // 8] &= ~(1 << (7 - (block_num % 8)))

            # Mark boot block (0) and superblock (1) as allocated
            mark_allocated(0)
            mark_allocated(1)

            # Mark bitmap blocks as allocated
            for b in range(self.bitmap_start,
                           self.bitmap_start + self.bitmap_blocks):
                mark_allocated(b)

            # Mark inode blocks in each CG as allocated
            for cg in range(self.ncg):
                cg_start = self.firstcg + cg * self.cgfsize
                for b in range(cg_start, cg_start + self.cgisize):
                    mark_allocated(b)

            # Mark data blocks used by files/dirs as allocated
            for ino, (_, data_blocks) in inode_table.items():
                for bn, chunk in data_blocks:
                    nblocks = (len(chunk) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
                    for b in range(bn, bn + nblocks):
                        mark_allocated(b)

            # Count free DATA blocks (only data areas, not inode/metadata)
            free_blocks = 0
            for cg in range(self.ncg):
                cg_start = self.firstcg + cg * self.cgfsize
                data_start = cg_start + self.cgisize
                data_end = cg_start + self.cgfsize
                for b in range(data_start, min(data_end, self.fs_size)):
                    if bitmap[b // 8] & (1 << (7 - (b % 8))):
                        free_blocks += 1
            # Pad to block boundary
            padded = bitmap + b'\x00' * (self.bitmap_blocks * EFS_BLOCK_SIZE - len(bitmap))
            f.seek(self.bitmap_start * EFS_BLOCK_SIZE)
            f.write(padded[:self.bitmap_blocks * EFS_BLOCK_SIZE])

            # replsb at end of filesystem
            replsb = self.fs_size - 1

            # Write superblock
            sb_data = pack_superblock(
                fs_size=self.fs_size,
                firstcg=self.firstcg,
                cgfsize=self.cgfsize,
                cgisize=self.cgisize,
                ncg=self.ncg,
                bmsize=bm_bytes,
                tfree=free_blocks,
                tinode=free_inodes,
                bmblock=self.bitmap_start,
                replsb=replsb,
            )
            f.seek(sb_offset)
            f.write(sb_data)

            # Write superblock copy at replsb
            f.seek(replsb * EFS_BLOCK_SIZE)
            f.write(sb_data)

            # Extend file to full fs_size
            f.seek(self.fs_size * EFS_BLOCK_SIZE - 1)
            f.write(b'\x00')

        total_data = (self.cgfsize - self.cgisize) * self.ncg
        used_data = total_data - free_blocks
        print(f"  EFS image: {self.fs_size * EFS_BLOCK_SIZE // (1024*1024)}MB")
        print(f"  Data blocks: {used_data} used, {free_blocks} free "
              f"(of {total_data} total)")
        print(f"  Inodes: {len(inode_table)} used, {free_inodes} free")

        # ── Verification: read back and check critical structures ──
        self._verify_image(output_path, inode_table)

    def _verify_image(self, output_path, inode_table):
        """Read back the built image and verify critical structures."""
        print("\n  Verifying image...")
        errors = 0

        with open(output_path, 'rb') as f:
            # Check superblock
            f.seek(EFS_BLOCK_SIZE)
            sb_raw = f.read(EFS_BLOCK_SIZE)
            sb_fs_size = struct.unpack('>i', sb_raw[0:4])[0]
            sb_firstcg = struct.unpack('>i', sb_raw[4:8])[0]
            sb_cgfsize = struct.unpack('>i', sb_raw[8:12])[0]
            sb_cgisize = struct.unpack('>h', sb_raw[12:14])[0]
            sb_ncg = struct.unpack('>h', sb_raw[18:20])[0]
            sb_dirty = struct.unpack('>h', sb_raw[20:22])[0]
            sb_magic = struct.unpack('>I', sb_raw[28:32])[0]

            print(f"    Superblock: magic=0x{sb_magic:06x} "
                  f"fs_size={sb_fs_size} firstcg={sb_firstcg} "
                  f"cgfsize={sb_cgfsize} cgisize={sb_cgisize} "
                  f"ncg={sb_ncg} dirty={sb_dirty}")

            if sb_magic != EFS_MAGIC:
                print(f"    ERROR: bad magic (expected 0x{EFS_MAGIC:06x})")
                errors += 1
            if sb_dirty != 0:
                print(f"    ERROR: dirty flag set")
                errors += 1
            if sb_fs_size != sb_firstcg + sb_cgfsize * sb_ncg:
                print(f"    ERROR: fs_size != firstcg + cgfsize*ncg "
                      f"({sb_fs_size} != {sb_firstcg + sb_cgfsize * sb_ncg})")
                errors += 1

            # Verify checksum
            checksum = 0
            for i in range(0, 88, 2):
                word = struct.unpack('>H', sb_raw[i:i+2])[0]
                checksum ^= word
                sign = 1 if (checksum & 0x80000000) else 0
                checksum = ((checksum << 1) | sign) & 0xFFFFFFFF
            stored_cksum = struct.unpack('>I', sb_raw[88:92])[0]
            if checksum != stored_cksum:
                print(f"    ERROR: checksum mismatch "
                      f"(computed=0x{checksum:08x} stored=0x{stored_cksum:08x})")
                errors += 1
            else:
                print(f"    Checksum OK (0x{checksum:08x})")

            # Check inodes 2 (root) and 3 (dist/)
            ipcg = sb_cgisize * EFS_INOPBB
            for ino in [2, 3]:
                cg = ino // ipcg
                cgbb = (ino >> 2) % sb_cgisize
                bb = sb_firstcg + cg * sb_cgfsize + cgbb
                slot = ino & 0x3
                file_offset = bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE

                f.seek(file_offset)
                inode_raw = f.read(EFS_INODE_SIZE)

                di_mode = struct.unpack('>H', inode_raw[0:2])[0]
                di_nlink = struct.unpack('>h', inode_raw[2:4])[0]
                di_size = struct.unpack('>i', inode_raw[8:12])[0]
                di_numextents = struct.unpack('>h', inode_raw[28:30])[0]

                mode_type = (di_mode & S_IFMT)
                type_str = {S_IFDIR: 'DIR', S_IFREG: 'REG',
                            S_IFLNK: 'LNK'}.get(mode_type, f'0o{mode_type:o}')

                print(f"    Inode {ino} at block {bb} slot {slot} "
                      f"(offset {file_offset}):")
                print(f"      mode=0o{di_mode:06o} ({type_str}) "
                      f"nlink={di_nlink} size={di_size} "
                      f"extents={di_numextents}")

                if mode_type != S_IFDIR:
                    print(f"      ERROR: expected DIR (0o{S_IFDIR:06o})")
                    errors += 1
                if di_size & 0x1FF:
                    print(f"      ERROR: i_size & 511 = {di_size & 0x1FF} "
                          f"(must be 0!)")
                    errors += 1
                else:
                    print(f"      i_size check OK ({di_size} & 511 = 0)")

                # Dump extent data
                for ext_i in range(min(di_numextents, EFS_MAX_EXTENTS)):
                    ext_off = 32 + ext_i * 8
                    w1 = struct.unpack('>I', inode_raw[ext_off:ext_off+4])[0]
                    w2 = struct.unpack('>I', inode_raw[ext_off+4:ext_off+8])[0]
                    ex_magic = (w1 >> 24) & 0xFF
                    ex_bn = w1 & 0xFFFFFF
                    ex_length = (w2 >> 24) & 0xFF
                    ex_offset = w2 & 0xFFFFFF
                    print(f"      extent[{ext_i}]: bn={ex_bn} len={ex_length} "
                          f"off={ex_offset} magic={ex_magic}")

                    # Check first directory block for 0xBEEF magic
                    if ext_i == 0 and mode_type == S_IFDIR:
                        f.seek(ex_bn * EFS_BLOCK_SIZE)
                        dir_block = f.read(EFS_BLOCK_SIZE)
                        dir_magic = struct.unpack('>H', dir_block[0:2])[0]
                        dir_firstused = dir_block[2]
                        dir_slots = dir_block[3]
                        print(f"      dirblk[0]: magic=0x{dir_magic:04X} "
                              f"firstused={dir_firstused} slots={dir_slots}")
                        if dir_magic != EFS_DIRBLK_MAGIC:
                            print(f"      ERROR: bad dirblk magic!")
                            errors += 1

                # Hexdump the raw inode bytes
                hex_str = ' '.join(f'{b:02x}' for b in inode_raw[:32])
                print(f"      raw[0:32]:  {hex_str}")
                hex_str = ' '.join(f'{b:02x}' for b in inode_raw[32:48])
                print(f"      raw[32:48]: {hex_str}")

            # Compare what we wrote vs what's on disk for inode 3
            if 3 in inode_table:
                written_bytes = inode_table[3][0]
                cg = 3 // ipcg
                cgbb = (3 >> 2) % sb_cgisize
                bb = sb_firstcg + cg * sb_cgfsize + cgbb
                slot = 3 & 0x3
                file_offset = bb * EFS_BLOCK_SIZE + slot * EFS_INODE_SIZE
                f.seek(file_offset)
                disk_bytes = f.read(EFS_INODE_SIZE)
                if written_bytes == disk_bytes:
                    print(f"    Inode 3: written == disk bytes (MATCH)")
                else:
                    print(f"    ERROR: Inode 3 written != disk bytes!")
                    for i in range(EFS_INODE_SIZE):
                        if written_bytes[i] != disk_bytes[i]:
                            print(f"      byte {i}: wrote 0x{written_bytes[i]:02x} "
                                  f"read 0x{disk_bytes[i]:02x}")
                    errors += 1

        if errors:
            print(f"\n  VERIFICATION FAILED: {errors} error(s)")
        else:
            print(f"\n  VERIFICATION PASSED")


# ── Dist file collection ────────────────────────────────────────────

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
