"""pyirix.xfs.mkfs — create an IRIX-style XFS filesystem from scratch.

Modern mkfs.xfs only produces XFS v5 (CRC) with dir2 directories, which neither
the IRIX PROM nor the IRIX kernel can read. This module lays out the *original*
IRIX format: a version-4 superblock with the DIRV2 bit clear, so directories use
the V1 short-form / V1-leaf (magic 0xFEEB) format that pyirix.xfs reads and
writes. Field values are modelled on a real IRIX 6.5 disk (sb_versionnum=0x1094,
blocksize 4096, inodesize 256, sectsize 512).

Layout per allocation group (sector size 512, block size 4096):
    block 0 : superblock (sector 0) + AGF (1) + AGI (2) + AGFL (3)
    block 1 : bnobt leaf  (free space by block,  magic ABTB)
    block 2 : cntbt leaf  (free space by count,  magic ABTC)
    block 3 : inobt leaf  (inode B+tree,         magic IABT)
  AG 0 only:
    blocks 4..7         : first inode chunk (64 inodes); root inode = agino 64
    blocks 8..8+L-1     : internal log
    blocks 8+L..end     : free space
  AG n>0:
    blocks 4..end       : free space (no inodes)

The result round-trips through pyirix.xfs (read, list, create_file, mkdir).
IRIX-mount validation is a future step; the log is zeroed (clean) but not
written with a real log record.
"""

import os
import struct

from pyirix.xfs.constants import (
    XFS_SB_MAGIC, XFS_DINODE_MAGIC, XFS_AGF_MAGIC, XFS_AGI_MAGIC,
    XFS_ABTB_MAGIC, XFS_ABTC_MAGIC, XFS_IBT_MAGIC,
    XFS_DINODE_FMT_LOCAL, XFS_DINODE_FMT_EXTENTS,
    NULLAGBLOCK,
    S_IFDIR, S_IFREG,
    VHMAGIC,
)
from pyirix.xfs.ondisk import (
    pack_superblock, pack_agf, pack_agi, pack_inode_core,
    pack_btree_sblock, pack_alloc_rec, pack_inobt_rec_full,
)

SECTOR = 512
INODES_PER_CHUNK = 64

PTYPE_VOLHDR = 0
PTYPE_VOLUME = 6
PTYPE_XFS = 10


def _ilog2_ceil(n):
    """Smallest k with (1 << k) >= n."""
    k = 0
    while (1 << k) < n:
        k += 1
    return k


def _build_xfs_volume_header(total_sectors, xfs_start_sector, xfs_sectors):
    """SGI volume header advertising one XFS partition (type 10)."""
    data = bytearray(SECTOR)
    struct.pack_into('>I', data, 0, VHMAGIC)
    struct.pack_into('>h', data, 4, 0)   # rootpt
    struct.pack_into('>h', data, 6, 1)   # swappt
    struct.pack_into('>H', data, 24 + 16, SECTOR)  # dp_secbytes

    vd_off = 72
    data[vd_off:vd_off + 8] = b'sgilabel'
    struct.pack_into('>ii', data, vd_off + 8, 0, SECTOR)

    pt_off = vd_off + 15 * 16            # 312
    # partition 0: the XFS filesystem
    struct.pack_into('>iii', data, pt_off + 0 * 12,
                     xfs_sectors, xfs_start_sector, PTYPE_XFS)
    # partition 8: the volume header
    struct.pack_into('>iii', data, pt_off + 8 * 12,
                     xfs_start_sector, 0, PTYPE_VOLHDR)
    # partition 10: the whole volume
    struct.pack_into('>iii', data, pt_off + 10 * 12,
                     total_sectors, 0, PTYPE_VOLUME)

    # checksum: two's-complement negation of the sum of all 32-bit words
    csum_off = pt_off + 16 * 12          # 504
    total = 0
    for i in range(0, SECTOR, 4):
        total = (total + struct.unpack('>I', data[i:i + 4])[0]) & 0xFFFFFFFF
    struct.pack_into('>I', data, csum_off, (-total) & 0xFFFFFFFF)
    return bytes(data)


def _empty_inode(blocksize, mode, fmt, nlink, size, fork=b''):
    """Build one `inodesize`-byte inode: core + di_next_unlinked + data fork."""
    core = {
        'di_magic': XFS_DINODE_MAGIC, 'di_mode': mode, 'di_version': 1,
        # di_version=1 inodes carry the link count in di_onlink (offset 6);
        # mirror it into di_nlink too (matches real IRIX disks and pyirix's
        # init_inode), so the count is correct whichever field the reader uses.
        'di_format': fmt, 'di_onlink': (nlink if nlink <= 0xFFFF else 0),
        'di_uid': 0, 'di_gid': 0,
        'di_nlink': nlink, 'di_projid': 0,
        'di_atime_sec': 0, 'di_atime_nsec': 0, 'di_mtime_sec': 0,
        'di_mtime_nsec': 0, 'di_ctime_sec': 0, 'di_ctime_nsec': 0,
        'di_size': size, 'di_nblocks': 0, 'di_extsize': 0, 'di_nextents': 0,
        'di_anextents': 0, 'di_forkoff': 0, 'di_aformat': 0, 'di_dmevmask': 0,
        'di_dmstate': 0, 'di_flags': 0, 'di_gen': 0,
    }
    buf = bytearray(256)
    buf[0:96] = pack_inode_core(core)
    struct.pack_into('>I', buf, 96, 0xFFFFFFFF)   # di_next_unlinked = NULL
    buf[100:100 + len(fork)] = fork
    return bytes(buf)


def make_xfs_image(size_mb=16, blocksize=4096, agcount=1, versionnum=0x0004,
                   logblocks=None, with_volume_header=True, label=""):
    """Build an IRIX V1-directory XFS image and return it as bytes.

    versionnum defaults to 0x0004 (minimal version-4, DIRV2 clear -> V1
    directories, V1 inodes). This is what IRIX's own xfs_check accepts cleanly.
    Real IRIX 6.5 disks use 0x1094 (adds ATTR|ALIGN|EXTFLG), but ALIGN requires
    inode-chunk alignment we don't implement, so xfs_check flags it; pass 0x1094
    only if you specifically need to match that on-disk version word.
    Do NOT set NLINKBIT (0x20) here unless you also make v2 inodes.
    """
    if versionnum & 0x2000:
        raise ValueError("DIRV2 bit set — this builder makes V1 directories only")

    inodesize = 256
    inopblock = blocksize // inodesize
    blocklog = _ilog2_ceil(blocksize)
    inodelog = _ilog2_ceil(inodesize)
    inopblog = _ilog2_ceil(inopblock)
    sectlog = _ilog2_ceil(SECTOR)

    dblocks = (size_mb * 1024 * 1024) // blocksize
    agblocks = dblocks // agcount
    dblocks = agblocks * agcount               # trim remainder
    agblklog = _ilog2_ceil(agblocks)

    # AG0 reserved head: block0 headers, 1 bnobt, 2 cntbt, 3 inobt, 4..7 inodes
    inode_chunk_agbno = 4
    inode_chunk_blocks = INODES_PER_CHUNK // inopblock      # 4
    log_agbno = inode_chunk_agbno + inode_chunk_blocks      # 8
    if logblocks is None:
        logblocks = max(64, agblocks // 16)
    free0_agbno = log_agbno + logblocks
    if free0_agbno >= agblocks:
        raise ValueError("filesystem too small for log + metadata")

    rootino = (0 << (agblklog + inopblog)) | (inode_chunk_agbno * inopblock)  # 64
    rbmino = rootino + 1
    rsumino = rootino + 2

    logstart = (0 << agblklog) | log_agbno     # fsblock of the log

    # Free space per AG (AG-relative agbno extents)
    free_ag0 = (free0_agbno, agblocks - free0_agbno)
    free_agn = (inode_chunk_agbno, agblocks - inode_chunk_agbno)
    fdblocks = free_ag0[1] + (agcount - 1) * free_agn[1]

    # ── Superblock ──────────────────────────────────────────────────
    sb = {
        'sb_magicnum': XFS_SB_MAGIC, 'sb_blocksize': blocksize,
        'sb_dblocks': dblocks, 'sb_rblocks': 0, 'sb_rextents': 0,
        'sb_logstart': logstart, 'sb_rootino': rootino,
        'sb_rbmino': rbmino, 'sb_rsumino': rsumino, 'sb_rextsize': 1,
        'sb_agblocks': agblocks, 'sb_agcount': agcount, 'sb_rbmblocks': 0,
        'sb_logblocks': logblocks, 'sb_versionnum': versionnum,
        'sb_sectsize': SECTOR, 'sb_inodesize': inodesize,
        'sb_inopblock': inopblock,
        'sb_fname': label[:6], 'sb_fpack': '',
        'sb_blocklog': blocklog, 'sb_sectlog': sectlog,
        'sb_inodelog': inodelog, 'sb_inopblog': inopblog,
        'sb_agblklog': agblklog, 'sb_rextslog': 0, 'sb_inprogress': 0,
        'sb_imax_pct': 25,
        'sb_icount': INODES_PER_CHUNK, 'sb_ifree': INODES_PER_CHUNK - 3,
        'sb_fdblocks': fdblocks, 'sb_frextents': 0,
        'sb_uquotino': 0, 'sb_pquotino': 0, 'sb_qflags': 0, 'sb_flags': 0,
        'sb_shared_vn': 0, 'sb_inoalignmt': 0, 'sb_unit': 0, 'sb_width': 0,
        'sb_dirblklog': 0, 'sb_logsectlog': 0, 'sb_logsectsize': 0,
        'sb_logsunit': 0, 'sb_features2': 0,
        'sb_uuid': b'pyirixXFSv1fixt!',   # 16 bytes, fixed for reproducibility
    }
    sb_bytes = pack_superblock(sb)

    img = bytearray(dblocks * blocksize)

    def put(block_in_ag, agno, data, sector=0):
        off = (agno * agblocks + block_in_ag) * blocksize + sector * SECTOR
        img[off:off + len(data)] = data

    for agno in range(agcount):
        is_ag0 = (agno == 0)
        free = free_ag0 if is_ag0 else free_agn

        # superblock copy + AG headers in block 0
        put(0, agno, sb_bytes, sector=0)
        agf = {
            'agf_magicnum': XFS_AGF_MAGIC, 'agf_versionnum': 1,
            'agf_seqno': agno, 'agf_length': agblocks,
            'agf_bno_root': 1, 'agf_cnt_root': 2,
            'agf_spare0': 0, 'agf_bno_level': 1, 'agf_cnt_level': 1,
            'agf_spare1': 0, 'agf_flfirst': 0, 'agf_fllast': 0,
            'agf_flcount': 0, 'agf_freeblks': free[1], 'agf_longest': free[1],
        }
        put(0, agno, pack_agf(agf), sector=1)

        if is_ag0:
            agi = {
                'agi_magicnum': XFS_AGI_MAGIC, 'agi_versionnum': 1,
                'agi_seqno': agno, 'agi_length': agblocks,
                'agi_count': INODES_PER_CHUNK, 'agi_root': 3, 'agi_level': 1,
                'agi_freecount': INODES_PER_CHUNK - 3, 'agi_newino': rootino,
                'agi_dirino': NULLAGBLOCK,
                'agi_unlinked': [NULLAGBLOCK] * 64,
            }
        else:
            agi = {
                'agi_magicnum': XFS_AGI_MAGIC, 'agi_versionnum': 1,
                'agi_seqno': agno, 'agi_length': agblocks,
                'agi_count': 0, 'agi_root': 3, 'agi_level': 1,
                'agi_freecount': 0, 'agi_newino': NULLAGBLOCK,
                'agi_dirino': NULLAGBLOCK,
                'agi_unlinked': [NULLAGBLOCK] * 64,
            }
        put(0, agno, pack_agi(agi), sector=2)

        # AGFL (sector 3): empty free list
        put(0, agno, b'\xff' * SECTOR, sector=3)

        # bnobt + cntbt leaves: one free-space record each
        leaf = bytearray(blocksize)
        leaf[0:16] = pack_btree_sblock({
            'bb_magic': XFS_ABTB_MAGIC, 'bb_level': 0, 'bb_numrecs': 1,
            'bb_leftsib': NULLAGBLOCK, 'bb_rightsib': NULLAGBLOCK})
        leaf[16:24] = pack_alloc_rec(free[0], free[1])
        put(1, agno, bytes(leaf))

        leaf = bytearray(blocksize)
        leaf[0:16] = pack_btree_sblock({
            'bb_magic': XFS_ABTC_MAGIC, 'bb_level': 0, 'bb_numrecs': 1,
            'bb_leftsib': NULLAGBLOCK, 'bb_rightsib': NULLAGBLOCK})
        leaf[16:24] = pack_alloc_rec(free[0], free[1])
        put(2, agno, bytes(leaf))

        # inobt leaf
        leaf = bytearray(blocksize)
        if is_ag0:
            leaf[0:16] = pack_btree_sblock({
                'bb_magic': XFS_IBT_MAGIC, 'bb_level': 0, 'bb_numrecs': 1,
                'bb_leftsib': NULLAGBLOCK, 'bb_rightsib': NULLAGBLOCK})
            # inodes 64,65,66 used -> bits 0,1,2 clear; rest free
            leaf[16:32] = pack_inobt_rec_full({
                'ir_startino': inode_chunk_agbno * inopblock,
                'ir_freecount': INODES_PER_CHUNK - 3,
                'ir_free': 0xFFFFFFFFFFFFFFF8})
        else:
            leaf[0:16] = pack_btree_sblock({
                'bb_magic': XFS_IBT_MAGIC, 'bb_level': 0, 'bb_numrecs': 0,
                'bb_leftsib': NULLAGBLOCK, 'bb_rightsib': NULLAGBLOCK})
        put(3, agno, bytes(leaf))

    # ── AG0 inode chunk: every slot needs a valid inode header ────────
    # XFS requires ALL inodes in an allocated chunk to carry the di_magic /
    # di_version header, even free ones (IRIX xfs_check fails otherwise). Free
    # inodes are headers with di_mode == 0; the inobt free bitmap marks them.
    base = inode_chunk_agbno * blocksize
    free_inode = bytearray(inodesize)
    struct.pack_into('>H', free_inode, 0, XFS_DINODE_MAGIC)
    free_inode[4] = 1                                  # di_version = 1
    struct.pack_into('>I', free_inode, 96, 0xFFFFFFFF)  # di_next_unlinked = NULL
    for slot in range(INODES_PER_CHUNK):
        img[base + slot * inodesize:base + slot * inodesize + inodesize] = free_inode

    # slot 0: root — empty V1 short-form directory (parent_ino(8) + count(1))
    root_fork = struct.pack('>Q', rootino) + bytes([0])
    root_inode = _empty_inode(blocksize, S_IFDIR | 0o755,
                              XFS_DINODE_FMT_LOCAL, 2, len(root_fork), root_fork)
    img[base + 0 * inodesize:base + 0 * inodesize + 256] = root_inode
    # slots 1,2: rbmino / rsumino placeholders (extents format, size 0)
    rbm = _empty_inode(blocksize, S_IFREG | 0o600, XFS_DINODE_FMT_EXTENTS, 1, 0)
    rsum = _empty_inode(blocksize, S_IFREG | 0o600, XFS_DINODE_FMT_EXTENTS, 1, 0)
    img[base + 1 * inodesize:base + 1 * inodesize + 256] = rbm
    img[base + 2 * inodesize:base + 2 * inodesize + 256] = rsum
    # log + remaining slots stay clean (zeroed log; free inodes have headers)

    if not with_volume_header:
        return bytes(img)

    xfs_start_sector = 64                       # 32 KiB, 4096-aligned
    xfs_sectors = len(img) // SECTOR
    total_sectors = xfs_start_sector + xfs_sectors
    vh = _build_xfs_volume_header(total_sectors, xfs_start_sector, xfs_sectors)
    out = bytearray(total_sectors * SECTOR)
    out[0:SECTOR] = vh
    out[xfs_start_sector * SECTOR:] = img
    return bytes(out)


def mkfs_xfs(output_path, **kwargs):
    """Write an IRIX V1-directory XFS image to `output_path`. See make_xfs_image."""
    data = make_xfs_image(**kwargs)
    with open(output_path, 'wb') as f:
        f.write(data)
    return output_path
