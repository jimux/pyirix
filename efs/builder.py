"""pyirix.efs.builder — create SGI EFS filesystem images from scratch.

This is the canonical EFS image builder (an mkfs-style tool): assemble files,
directories, and symlinks, then write a raw EFS image, optionally wrapped in an
SGI volume header so the IRIX `dksc` driver / PROM will recognise it.

Moved here from pyirix.dist.combine so it is a first-class pyirix.efs capability
(single source of truth); combine.py now re-exports from this module.
"""

import os
import struct
import time

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

class EFSFullError(RuntimeError):
    """The volume has no data block left to give (or none inside the volume).

    Raised instead of walking past ``fs_size``: an allocation outside the
    filesystem is not a smaller filesystem, it is silent corruption (and, on
    the last block, a file overwritten by the revolving superblock).
    """


class EFSReadbackError(RuntimeError):
    """A file staged into the image does not read back byte-identical."""


class EFSImageBuilder:
    """Builds a correct SGI EFS filesystem image from files.

    Uses the correct on-disk formats:
    - Extent: word1 = (magic<<24)|bn, word2 = (length<<24)|offset
    - Directory: 0xBEEF slot-based blocks
    - Superblock cgisize = inode BLOCKS per CG (not total inodes)
    """

    def __init__(self, total_blocks, auto_size=False):
        # auto_size: treat total_blocks as a SEED and grow the volume until the
        # plan fits (set only when the caller has no size in mind; an explicit
        # budget is honoured and a volume that cannot hold the tree is refused).
        self.total_blocks = total_blocks
        self.auto_size = auto_size
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

    def _allocate_run(self, num_blocks, max_run):
        """Allocate *num_blocks* data blocks in runs of at most *max_run*.

        Walks the cylinder groups in order, skipping each CG's inode blocks,
        and STOPS AT THE END OF THE VOLUME: the last block (``fs_size - 1``) is
        the revolving superblock, which ``build`` writes after the file data, so
        a file placed there reads back with the superblock's bytes; anything
        past ``fs_size`` is outside the filesystem entirely.  Both used to be
        handed out silently when the volume was sized too small (measured on
        the real Foundation 1 tree: ``x_eoe.sw64`` got blocks 1,079,087..1,079,376
        of a 1,079,232-block volume).  Running out is an error, not an
        allocation.
        """
        if num_blocks == 0:
            return []

        # The revolving superblock lives in the volume's last block.
        usable_end = self.fs_size - 1

        extents = []
        remaining = num_blocks
        logical_offset = 0

        while remaining > 0:
            cg = (self.next_data_block - self.firstcg) // self.cgfsize
            if cg < 0:
                cg = 0
            if cg >= self.ncg:
                raise EFSFullError(
                    f"EFS filesystem full: need {remaining} more blocks, "
                    f"no cylinder groups left (fs_size={self.fs_size}, "
                    f"ncg={self.ncg}, cgfsize={self.cgfsize})")

            data_start = self.firstcg + cg * self.cgfsize + self.cgisize
            data_end = min(self.firstcg + (cg + 1) * self.cgfsize, usable_end)

            # In the inode area -> skip to this CG's data area.
            if self.next_data_block < data_start:
                self.next_data_block = data_start

            # This CG is exhausted -> start the next one.
            if self.next_data_block >= data_end:
                self.next_data_block = (self.firstcg + (cg + 1) * self.cgfsize
                                        + self.cgisize)
                continue

            length = min(remaining, max_run, data_end - self.next_data_block)
            extents.append((self.next_data_block, length, logical_offset))
            self.next_data_block += length
            remaining -= length
            logical_offset += length

        return extents

    def _allocate_blocks(self, num_blocks):
        """Allocate contiguous blocks, return list of (bn, length, offset).

        Allocates data blocks linearly across CGs, skipping the inode
        blocks at the start of each CG and the revolving superblock.
        """
        return self._allocate_run(num_blocks, EFS_MAX_EXTENT_LENGTH)

    # Max blocks per indirect extent (from IRIX kernel efs_ino.h)
    EFS_MAXINDIRBBS = 64

    def _allocate_indirect_blocks(self, num_blocks):
        """Allocate blocks for indirect extent table.

        Like _allocate_blocks but limits each run to EFS_MAXINDIRBBS (64)
        instead of EFS_MAX_EXTENT_LENGTH (248). Returns list of (bn, length, offset).
        """
        return self._allocate_run(num_blocks, self.EFS_MAXINDIRBBS)

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
        total_items = len(self.files) + len(self.dirs)
        inode_table = self._prepare()

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
        if self.indirect_count:
            print(f"  Files with indirect extents: {self.indirect_count}")

        self._write(output_path, inode_table)
        self.verify_readback(output_path)

    #: How many times an auto-sized volume may grow before the plan is refused.
    MAX_GROW_ROUNDS = 8

    def _prepare(self):
        """Compute the geometry and plan the layout of the whole tree.

        With ``auto_size`` the volume grows until the plan fits, which is what
        the no-budget caller asked for; the plan is then RE-checked, because a
        bigger volume moves every CG boundary.  With an explicit size, a tree
        that does not fit raises :class:`EFSFullError` -- refusing is the point:
        the previous behaviour was to allocate past the end of the volume.
        """
        for _round in range(self.MAX_GROW_ROUNDS):
            self._compute_geometry()
            try:
                inode_table = self._plan()
            except EFSFullError:
                if not self.auto_size:
                    raise
                self.total_blocks = self._grown_total_blocks()
                continue
            if self.next_data_block <= self.fs_size - 1:
                return inode_table
            if not self.auto_size:
                raise EFSFullError(
                    f"EFS plan needs block {self.next_data_block} but the "
                    f"volume ends at {self.fs_size}")
            self.total_blocks = self._grown_total_blocks()
        raise EFSFullError(
            f"EFS volume still does not fit after {self.MAX_GROW_ROUNDS} "
            f"rounds (total_blocks={self.total_blocks}, "
            f"fs_size={self.fs_size})")

    def _grown_total_blocks(self):
        """The smallest volume the current plan needs, with a little margin.

        The shortfall is measured from where the plan actually ran out, so one
        round is normally enough; the margin covers the per-CG inode blocks the
        bigger volume brings with it.
        """
        short = max(1, self.next_data_block - (self.fs_size - 1))
        # Each new block of volume also pays for cgisize/ncg of inode blocks.
        per_block = 1.0 + self.cgisize / float(self.ncg)
        extra = int(short * per_block) + self.ncg * self.cgisize + 16
        return self.total_blocks + extra

    def _plan(self):
        """Assign inodes, extents and data blocks for every old and new file.

        Returns the inode table: ``inode_num -> (inode_bytes, [(bn, bytes)])``.
        Allocates from ``next_data_block``, which the caller has reset.
        """

        # Data blocks start after inode blocks in first CG
        self.next_data_block = self.firstcg + self.cgisize

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

        self.indirect_count = indirect_count
        return inode_table

    def _write(self, output_path, inode_table):
        """Write the planned layout to *output_path* as a raw EFS image."""
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

            # Mark the revolving superblock (fs_size - 1) as allocated: it is
            # not file data, and a later writer that trusts this bitmap must
            # never put a file there (the live allocator in
            # pyirix.efs.operations allocates from this bitmap).
            mark_allocated(self.fs_size - 1)

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

    def _expected_files(self):
        """The guest path -> bytes map the image must read back as.

        A symlink's stored payload is its target's ASCII bytes (see
        ``_plan``), so the same rule applies here; the reader returns that
        payload as file data.
        """
        out = {}
        for path, (mode, _size, data, link_target) in self.files.items():
            if mode & S_IFMT == S_IFLNK:
                out[path] = link_target.encode('ascii', errors='replace')
            else:
                out[path] = data
        return out

    def verify_readback(self, output_path):
        """Read every regular file back through pyirix.efs.reader and compare.

        Reads the image it has just written, in this process, with the same
        reader the mount/extract path uses.  A file whose bytes do not survive
        the round trip is a builder defect that a size check cannot see (the
        corrupted ``x_eoe.sw64`` of the Foundation 1 tree read back the RIGHT
        length with the superblock's bytes inside it), so this raises
        :class:`EFSReadbackError` rather than letting a corrupt medium ship.
        """
        mismatched = verify_efs_readback(
            output_path, expected=self._expected_files())
        if mismatched:
            detail = ", ".join(mismatched[:5])
            if len(mismatched) > 5:
                detail += ", ... (%d more)" % (len(mismatched) - 5)
            raise EFSReadbackError(
                f"{len(mismatched)} file(s) in {output_path} do not read back "
                f"byte-identical to their source: {detail}")
        print(f"  Read-back: {len(self.files)}/{len(self.files)} files "
              f"byte-identical")


def verify_efs_readback(image_path, expected):
    """Return the paths in *image_path* that differ from *expected*.

    *expected* maps guest path -> bytes (the tree that was staged, symlink
    payloads included).  Every entry is re-read from the image through
    :mod:`pyirix.efs.reader`; a missing file, a short read or a different byte
    range lands in the result.  The returned list is empty when the medium is
    faithful, so the caller decides whether to raise (the builder does) or
    report.
    """
    from pyirix.efs import reader as efs_reader

    wrong = []
    with open(image_path, 'rb') as f:
        found = efs_reader.find_efs_partition(f)
        if found is None:
            return sorted(expected) or ["<no EFS partition>"]
        part_offset = found[0]
        sb = efs_reader.read_superblock(f, part_offset)

        seen = {}

        def walk(ino, prefix):
            inode = efs_reader.read_inode(f, part_offset, sb, ino)
            if inode is None:
                return
            for name, child in efs_reader.read_dir_entries(
                    f, part_offset, sb, inode):
                path = prefix + "/" + name
                child_inode = efs_reader.read_inode(f, part_offset, sb, child)
                if child_inode is None:
                    continue
                if child_inode['mode'] & S_IFMT == S_IFDIR:
                    walk(child, path)
                else:
                    seen[path] = efs_reader.read_file_data(
                        f, part_offset, sb, child_inode)

        walk(EFS_ROOT_INODE, "")

    for path, want in expected.items():
        got = seen.get(path)
        if got != want:
            wrong.append(path)
    return wrong


# ── High-level mkfs convenience ──────────────────────────────────────

def _estimate_efs_blocks(files, symlinks, dirs):
    """Blocks needed to hold this tree, from the builder's own geometry rules.

    The old form was ``data + n_dirs + n_nodes // 8 + 256``: it did not know
    that every cylinder group spends ``cgisize`` blocks on inodes, that each
    ``firstcg`` block is metadata, that a file with more than 12 extents also
    spends a block on its extent table, or that the volume's last block is the
    revolving superblock.  On the real Foundation 1 tree that came out TWO
    blocks larger than ``fs_size`` while the layout needed 74 more data blocks
    than the CG data areas held, so the allocator ran off the end.  Estimating
    from the geometry removes the shortfall at its source; ``EFSImageBuilder``
    still grows the volume if a tree beats this estimate, and refuses instead
    of allocating past the end.
    """
    import math

    files = files or {}
    symlinks = symlinks or {}
    dirs = list(dirs or [])

    # Directories: the explicit ones plus every parent a file or symlink
    # implies (add_file creates those), plus the root.
    alldirs = set(dirs)
    for path in list(files) + list(symlinks):
        parent = os.path.dirname(path) or '/'
        while parent and parent != '/':
            alldirs.add(parent)
            parent = os.path.dirname(parent) or '/'
    n_dirs = len(alldirs) + 1               # + root

    # Data: file blocks, symlink payload blocks, and one dir block per dir
    # (build_dir_blocks always emits at least one block).
    data = 0
    extents_per_file = []
    for d in files.values():
        blocks = max(1, math.ceil(len(d) / EFS_BLOCK_SIZE)) if d else 0
        data += blocks
        extents_per_file.append(blocks)
    for _t in symlinks.values():
        data += 1
        extents_per_file.append(1)
    data += n_dirs

    n_nodes = len(files) + len(symlinks) + n_dirs
    ncg = max(1, (n_nodes + 128 + EFS_INOPBB * 8 - 1) // (EFS_INOPBB * 8))
    cgisize = 8

    # Extent-table blocks: a file needs one for every 64 extents past the
    # twelfth.  A file's data can be split by CG boundaries, so allow one
    # extent per 248 blocks plus two per CG it might cross.
    tables = 0
    for blocks in extents_per_file:
        if blocks <= EFS_MAX_EXTENTS:
            continue
        est_extents = (math.ceil(blocks / EFS_MAX_EXTENT_LENGTH)
                       + 2 * ncg)
        tables += math.ceil(est_extents / (EFS_BLOCK_SIZE // 8))
    data += tables

    # Solve for a total that leaves `data` in the CG data areas plus the
    # reserved last block, with the bitmap and inode blocks paid for.  The
    # bitmap grows with the total, so iterate to a fixed point.
    total = data + 1 + ncg * cgisize + 2 + 256
    for _ in range(16):
        bitmap_blocks = (((total + 7) // 8) + EFS_BLOCK_SIZE - 1) // EFS_BLOCK_SIZE
        firstcg = 2 + bitmap_blocks
        need = data + 1 + ncg * cgisize + firstcg
        if need <= total:
            break
        total = need
    return max(512, total)


def mkfs_efs(output_path, files=None, symlinks=None, dirs=None,
             size_blocks=None, with_volume_header=True, quiet=True,
             modes=None):
    """Create an SGI EFS filesystem image from scratch.

    files     : dict {path: bytes}        — regular files (parents auto-created)
    modes     : dict {path: mode}         — per-file permissions, optional.  A
                staged EXECUTABLE that is not executable mounts fine and then
                fails at run time, which reads as a caller's result rather than
                as a staging defect; without this the caller has to rebuild the
                image by hand to get the bits right.  Values are the usual
                permission bits (0o755); the file type is OR'd in here so a
                caller cannot accidentally ask for a non-regular file.
    symlinks  : dict {path: target_str}   — symbolic links
    dirs      : iterable of paths         — explicit (possibly empty) directories
    size_blocks   : total EFS basic blocks; auto-sized if None
    with_volume_header : if True, wrap the EFS partition in an SGI volume header
                         at sector EFS_PARTITION_START (a real bootable-style
                         disk image); if False, write a raw EFS partition.

    Returns the path written.
    """
    files = files or {}
    symlinks = symlinks or {}
    dirs = list(dirs or [])

    # With no explicit budget the estimate is only a SEED: the builder grows the
    # volume until the whole tree fits (the estimate cannot know the per-CG
    # inode blocks and indirect-extent tables the layout will need).  An
    # explicit size_blocks is honoured, and a tree that does not fit is refused.
    blocks = size_blocks or _estimate_efs_blocks(files, symlinks, dirs)
    b = EFSImageBuilder(blocks, auto_size=size_blocks is None)
    for p in dirs:
        b.add_directory(p)
    for p, data in files.items():
        _m = (modes or {}).get(p)
        if _m is None:
            b.add_file(p, data)
        else:
            b.add_file(p, data, mode=(_m & 0o7777) | 0o100000)
    for p, target in symlinks.items():
        b.add_symlink(p, target)

    import io, contextlib
    sink = io.StringIO()

    if not with_volume_header:
        with (contextlib.redirect_stdout(sink) if quiet else contextlib.nullcontext()):
            b.build(output_path)
        return output_path

    # Wrap in an SGI volume header (mirrors combine.cmd_build assembly).
    tmp = output_path + ".efs.tmp"
    try:
        with (contextlib.redirect_stdout(sink) if quiet else contextlib.nullcontext()):
            b.build(tmp)
        actual_total = EFS_PARTITION_START + b.fs_size
        with open(output_path, 'wb') as out:
            out.write(build_volume_header(actual_total, EFS_PARTITION_START))
            out.write(b'\x00' * (EFS_PARTITION_START * SECTOR_SIZE - VH_SIZE))
            with open(tmp, 'rb') as efs_in:
                while True:
                    chunk = efs_in.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return output_path

