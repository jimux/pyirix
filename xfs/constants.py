"""XFS on-disk constants, magic numbers, format codes, and exceptions.

All values from IRIX 6.5.7m xfs headers (irix/kern/fs/xfs/).
"""

import struct

# ── Superblock ──────────────────────────────────────────────────────

XFS_SB_MAGIC = 0x58465342          # 'XFSB'

# Version numbers (sb_versionnum low nibble)
XFS_SB_VERSION_1 = 1               # 5.3, 6.0.1, 6.1
XFS_SB_VERSION_2 = 2               # 6.2 with attrs
XFS_SB_VERSION_3 = 3               # 6.2 with nlink v2
XFS_SB_VERSION_4 = 4               # 6.2+ bitmask features

# Feature bits (sb_versionnum, version 4 only)
XFS_SB_VERSION_ATTRBIT    = 0x0010
XFS_SB_VERSION_NLINKBIT   = 0x0020
XFS_SB_VERSION_QUOTABIT   = 0x0040
XFS_SB_VERSION_ALIGNBIT   = 0x0080
XFS_SB_VERSION_DALIGNBIT  = 0x0100
XFS_SB_VERSION_SHAREDBIT  = 0x0200
XFS_SB_VERSION_EXTFLGBIT  = 0x1000
XFS_SB_VERSION_DIRV2BIT   = 0x2000

# Bits that PROM/SASH will accept
XFS_SB_VERSION_OKSASHBITS = 0x3FFF

# ── Inode ───────────────────────────────────────────────────────────

XFS_DINODE_MAGIC = 0x494E          # 'IN'

# Data fork format codes (di_format / di_aformat)
XFS_DINODE_FMT_DEV     = 0
XFS_DINODE_FMT_LOCAL   = 1
XFS_DINODE_FMT_EXTENTS = 2
XFS_DINODE_FMT_BTREE   = 3
XFS_DINODE_FMT_UUID    = 4

# Inode core size (before data fork)
XFS_DINODE_CORE_SIZE = 96          # xfs_dinode_core_t
XFS_DINODE_UNLINKED_OFF = 96       # di_next_unlinked offset
XFS_DATA_FORK_OFFSET = 100         # 96 + 4 (core + next_unlinked)

# ── B+Tree ──────────────────────────────────────────────────────────

XFS_BMAP_MAGIC  = 0x424D4150      # 'BMAP' — extent map B+tree
XFS_ABTB_MAGIC  = 0x41425442      # 'ABTB' — free space by block#
XFS_ABTC_MAGIC  = 0x41425443      # 'ABTC' — free space by count
XFS_IBT_MAGIC   = 0x49414254      # 'IABT' — inode B+tree

# B+tree block header sizes
XFS_BTREE_SBLOCK_SIZE = 16        # short-form: magic(4)+level(2)+numrecs(2)+left(4)+right(4)
XFS_BTREE_LBLOCK_SIZE = 24        # long-form:  magic(4)+level(2)+numrecs(2)+left(8)+right(8)
XFS_BMDR_BLOCK_SIZE   = 4         # in-inode root: level(2)+numrecs(2)

# Null pointers
NULLFSBLOCK  = (1 << 64) - 1
NULLAGBLOCK  = (1 << 32) - 1
NULLAGNUMBER = (1 << 32) - 1

# ── AG Headers ──────────────────────────────────────────────────────

XFS_AGF_MAGIC = 0x58414746        # 'XAGF'
XFS_AGI_MAGIC = 0x58414749        # 'XAGI'

# AG sector layout
XFS_SB_DADDR   = 0               # superblock copy
XFS_AGF_DADDR  = 1               # AGF
XFS_AGI_DADDR  = 2               # AGI
XFS_AGFL_DADDR = 3               # free list

# AGF B+tree indices
XFS_BTNUM_BNO = 0                # by block number
XFS_BTNUM_CNT = 1                # by count

# AG fixed block numbers (in fsblocks from AG start)
# These assume the 4-sector header area occupies 1 fsblock (4KB blocks / 512B sectors)
# or 4 fsblocks (512B blocks). For standard 4KB blocks:
XFS_BNO_BLOCK = 4                # first B+tree root after AGFL
XFS_CNT_BLOCK = 5
XFS_IBT_BLOCK = 6
XFS_PREALLOC_BLOCKS = 7          # first usable data block

# ── Allocation ──────────────────────────────────────────────────────

# Alloc B+tree record size
XFS_ALLOC_REC_SIZE = 8           # ar_startblock(4) + ar_blockcount(4)
XFS_ALLOC_KEY_SIZE = 8           # same as record for BNO; for CNT: count(4)+block(4)
XFS_ALLOC_PTR_SIZE = 4           # AG-relative block number

# ── Inode Allocation ────────────────────────────────────────────────

XFS_INODES_PER_CHUNK = 64        # fixed: 8 * sizeof(uint64)
XFS_INOBT_REC_SIZE  = 16         # ir_startino(4) + ir_freecount(4) + ir_free(8)
XFS_INOBT_KEY_SIZE  = 4          # ir_startino only
XFS_INOBT_PTR_SIZE  = 4          # AG-relative block
XFS_INOBT_ALL_FREE  = 0xFFFFFFFFFFFFFFFF

# ── Directory V1 (IRIX) ────────────────────────────────────────────

XFS_DIR_LEAF_MAGIC = 0xFEEB      # V1 leaf directory block
XFS_DA_NODE_MAGIC  = 0xFEBE      # DA B+tree internal node

# V1 shortform directory
XFS_DIR_SF_HDR_SIZE   = 9        # parent(8) + count(1)
XFS_DIR_SF_ENTRY_BASE = 9        # inumber(8) + namelen(1)

# V1 leaf directory
XFS_DIR_LEAF_HDR_SIZE   = 32     # da_blkinfo(12) + count(2) + namebytes(2) +
                                  # firstused(2) + holes(1) + pad(1) + freemap(12)
XFS_DIR_LEAF_ENTRY_SIZE = 8      # hashval(4) + nameidx(2) + namelen(1) + pad(1)
XFS_DIR_LEAF_NAME_BASE  = 8      # inumber(8), then name bytes follow

# DA blkinfo size (common prefix for dir/attr B+tree blocks)
XFS_DA_BLKINFO_SIZE = 12         # forw(4) + back(4) + magic(2) + pad(2)

# ── Directory V2 ───────────────────────────────────────────────────

XFS_DIR2_BLOCK_MAGIC = 0x58443242  # 'XD2B'
XFS_DIR2_DATA_MAGIC  = 0x58443244  # 'XD2D'
XFS_DIR2_FREE_MAGIC  = 0x58443246  # 'XD2F'
XFS_DIR2_FREE_TAG    = 0xFFFF

# Dir2 data header: magic(4) + 3 bestfree entries (6 bytes each)
XFS_DIR2_DATA_HDR_SIZE = 16      # 4 + 3*(2+2) = 16... actually 4 + 3*4 = 16
# Each bestfree: offset(2) + length(2) = 4 bytes, 3 of them = 12, + magic(4) = 16

# Dir2 block tail (at end of block): count(4) + stale(4)
XFS_DIR2_BLOCK_TAIL_SIZE = 8

# Dir2 leaf entry: hashval(4) + address(4) = 8 bytes
XFS_DIR2_LEAF_ENTRY_SIZE = 8

# Dir2 leaf offset (byte offset where leaf blocks start in dir address space)
XFS_DIR2_LEAF_OFFSET = 32 * (1 << 30)  # 32GB

# Dir2 shortform (xfs_dir2_sf.h)
XFS_DIR2_SF_HDR_SIZE_4  = 6   # count(1) + i8count(1) + parent4(4)
XFS_DIR2_SF_HDR_SIZE_8  = 10  # count(1) + i8count(1) + parent8(8)
XFS_DIR2_MAX_SHORT_INUM = 0xFFFFFFFF

# Dir2 data entry virtual offsets (for shortform offset field)
XFS_DIR2_DATA_DOT_OFFSET    = 16  # sizeof(dir2_data_hdr)
XFS_DIR2_DATA_DOTDOT_OFFSET = 32  # 16 + entsize(1) = 16 + 16
XFS_DIR2_DATA_FIRST_OFFSET  = 48  # 32 + entsize(2) = 32 + 16

# Dir2 filetype values (used when FTYPE feature is enabled)
XFS_DIR3_FT_UNKNOWN  = 0
XFS_DIR3_FT_REG_FILE = 1
XFS_DIR3_FT_DIR      = 2
XFS_DIR3_FT_CHRDEV   = 3
XFS_DIR3_FT_BLKDEV   = 4
XFS_DIR3_FT_FIFO     = 5
XFS_DIR3_FT_SOCK     = 6
XFS_DIR3_FT_SYMLINK  = 7

# sb_features2 bits
XFS_SB_VERSION2_FTYPE = 0x0200

# ── File Types ──────────────────────────────────────────────────────

S_IFMT  = 0o170000
S_IFIFO = 0o010000
S_IFCHR = 0o020000
S_IFDIR = 0o040000
S_IFBLK = 0o060000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFSOCK = 0o140000
S_IFMNT = 0o160000               # SGI-specific mount point

# ── Volume Header ──────────────────────────────────────────────────

SECTOR_SIZE = 512
VHMAGIC = 0x0BE5A941
NVDIR   = 15
NPARTAB = 16

PTYPE_VOLHDR = 0
PTYPE_RAW    = 3
PTYPE_SYSV   = 5
PTYPE_VOLUME = 6
PTYPE_EFS    = 7
PTYPE_XFS    = 10
PTYPE_XFSLOG = 11

QCOW2_MAGIC = b'QFI\xfb'

# ── Exceptions ──────────────────────────────────────────────────────

class XFSError(Exception):
    """Base exception for XFS operations."""
    pass

class XFSCorruptionError(XFSError):
    """On-disk data is corrupt or inconsistent."""
    pass

class XFSNoSpaceError(XFSError):
    """No free blocks or inodes available."""
    pass

class XFSPathError(XFSError):
    """Path not found or invalid."""
    pass

class XFSExistsError(XFSError):
    """File or directory already exists."""
    pass

class XFSNotEmptyError(XFSError):
    """Directory is not empty."""
    pass
