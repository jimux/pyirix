"""On-disk structure parse/pack pairs for XFS.

All structures are big-endian. Parse functions return dicts.
Pack functions return bytes. Round-trip: pack(parse(raw)) == raw.

Based on IRIX 6.5.7m xfs headers.
"""

import struct

from pyirix.xfs.constants import (
    XFS_SB_MAGIC, XFS_DINODE_MAGIC,
    XFS_AGF_MAGIC, XFS_AGI_MAGIC,
    XFS_BTREE_SBLOCK_SIZE, XFS_BTREE_LBLOCK_SIZE,
    XFS_BMDR_BLOCK_SIZE,
    NULLFSBLOCK, NULLAGBLOCK,
)

# ── Superblock ──────────────────────────────────────────────────────

# Full superblock field table: (offset, size, name, struct_fmt)
_SB_FIELDS = [
    (0x00, 4, 'sb_magicnum',   '>I'),
    (0x04, 4, 'sb_blocksize',  '>I'),
    (0x08, 8, 'sb_dblocks',    '>Q'),
    (0x10, 8, 'sb_rblocks',    '>Q'),
    (0x18, 8, 'sb_rextents',   '>Q'),
    # 0x20: uuid (16 bytes) — stored as raw bytes
    (0x30, 8, 'sb_logstart',   '>Q'),
    (0x38, 8, 'sb_rootino',    '>Q'),
    (0x40, 8, 'sb_rbmino',     '>Q'),
    (0x48, 8, 'sb_rsumino',    '>Q'),
    (0x50, 4, 'sb_rextsize',   '>I'),
    (0x54, 4, 'sb_agblocks',   '>I'),
    (0x58, 4, 'sb_agcount',    '>I'),
    (0x5C, 4, 'sb_rbmblocks',  '>I'),
    (0x60, 4, 'sb_logblocks',  '>I'),
    (0x64, 2, 'sb_versionnum', '>H'),
    (0x66, 2, 'sb_sectsize',   '>H'),
    (0x68, 2, 'sb_inodesize',  '>H'),
    (0x6A, 2, 'sb_inopblock',  '>H'),
    # 0x6C: sb_fname (6 bytes)
    # 0x72: sb_fpack (6 bytes)
    (0x78, 1, 'sb_blocklog',   '>B'),
    (0x79, 1, 'sb_sectlog',    '>B'),
    (0x7A, 1, 'sb_inodelog',   '>B'),
    (0x7B, 1, 'sb_inopblog',   '>B'),
    (0x7C, 1, 'sb_agblklog',   '>B'),
    (0x7D, 1, 'sb_rextslog',   '>B'),
    (0x7E, 1, 'sb_inprogress', '>B'),
    (0x7F, 1, 'sb_imax_pct',   '>B'),
    (0x80, 8, 'sb_icount',     '>Q'),
    (0x88, 8, 'sb_ifree',      '>Q'),
    (0x90, 8, 'sb_fdblocks',   '>Q'),
    (0x98, 8, 'sb_frextents',  '>Q'),
    (0xA0, 8, 'sb_uquotino',   '>Q'),
    (0xA8, 8, 'sb_pquotino',   '>Q'),
    (0xB0, 2, 'sb_qflags',     '>H'),
    (0xB2, 1, 'sb_flags',      '>B'),
    (0xB3, 1, 'sb_shared_vn',  '>B'),
    (0xB4, 4, 'sb_inoalignmt', '>I'),
    (0xB8, 4, 'sb_unit',       '>I'),
    (0xBC, 4, 'sb_width',      '>I'),
    (0xC0, 1, 'sb_dirblklog',  '>B'),
    (0xC1, 1, 'sb_logsectlog', '>B'),
    (0xC2, 2, 'sb_logsectsize', '>H'),
    (0xC4, 4, 'sb_logsunit',   '>I'),
    (0xC8, 4, 'sb_features2',  '>I'),
]

_SB_SIZE = 0xCC  # minimum bytes we need to read (through sb_features2)


def parse_superblock(data):
    """Parse XFS superblock from raw bytes (>= 193 bytes).

    Returns dict with all superblock fields plus 'sb_uuid' (bytes)
    and 'sb_fname'/'sb_fpack' (str).
    """
    if len(data) < _SB_SIZE:
        return None

    sb = {}
    for off, size, name, fmt in _SB_FIELDS:
        sb[name] = struct.unpack(fmt, data[off:off + size])[0]

    # UUID at offset 0x20 (16 bytes raw)
    sb['sb_uuid'] = data[0x20:0x30]

    # Filesystem name and pack name
    sb['sb_fname'] = data[0x6C:0x72].rstrip(b'\x00').decode('ascii', errors='replace')
    sb['sb_fpack'] = data[0x72:0x78].rstrip(b'\x00').decode('ascii', errors='replace')

    # Keep raw for round-trip
    sb['_raw'] = bytes(data[:max(256, len(data))])

    return sb


def pack_superblock(sb):
    """Pack superblock dict back to bytes.

    Starts from _raw if present, then overwrites all known fields.
    Returns 256 bytes minimum.
    """
    raw = sb.get('_raw', None)
    if raw:
        buf = bytearray(raw)
    else:
        buf = bytearray(256)

    # Ensure buffer is at least 256 bytes
    if len(buf) < 256:
        buf.extend(b'\x00' * (256 - len(buf)))

    for off, size, name, fmt in _SB_FIELDS:
        if name in sb:
            struct.pack_into(fmt, buf, off, sb[name])

    # UUID
    if 'sb_uuid' in sb:
        buf[0x20:0x30] = sb['sb_uuid']

    # Name fields (6 bytes each, null-padded)
    if 'sb_fname' in sb:
        fname = sb['sb_fname'].encode('ascii')[:6].ljust(6, b'\x00')
        buf[0x6C:0x72] = fname
    if 'sb_fpack' in sb:
        fpack = sb['sb_fpack'].encode('ascii')[:6].ljust(6, b'\x00')
        buf[0x72:0x78] = fpack

    return bytes(buf)


# ── AGF (AG Free Space Header) ──────────────────────────────────────

_AGF_FIELDS = [
    (0,  4, 'agf_magicnum',   '>I'),
    (4,  4, 'agf_versionnum', '>I'),
    (8,  4, 'agf_seqno',      '>I'),
    (12, 4, 'agf_length',     '>I'),
    (16, 4, 'agf_bno_root',   '>I'),   # agf_roots[0]
    (20, 4, 'agf_cnt_root',   '>I'),   # agf_roots[1]
    (24, 4, 'agf_spare0',     '>I'),
    (28, 4, 'agf_bno_level',  '>I'),   # agf_levels[0]
    (32, 4, 'agf_cnt_level',  '>I'),   # agf_levels[1]
    (36, 4, 'agf_spare1',     '>I'),
    (40, 4, 'agf_flfirst',    '>I'),
    (44, 4, 'agf_fllast',     '>I'),
    (48, 4, 'agf_flcount',    '>I'),
    (52, 4, 'agf_freeblks',   '>I'),
    (56, 4, 'agf_longest',    '>I'),
]

_AGF_SIZE = 60


def parse_agf(data):
    """Parse AGF header (60 bytes). Returns dict."""
    if len(data) < _AGF_SIZE:
        return None
    agf = {}
    for off, size, name, fmt in _AGF_FIELDS:
        agf[name] = struct.unpack(fmt, data[off:off + size])[0]
    return agf


def pack_agf(agf):
    """Pack AGF dict to bytes. Returns sector-sized (512) buffer."""
    buf = bytearray(512)
    for off, size, name, fmt in _AGF_FIELDS:
        if name in agf:
            struct.pack_into(fmt, buf, off, agf[name])
    return bytes(buf)


# ── AGI (AG Inode Header) ──────────────────────────────────────────

_AGI_FIELDS = [
    (0,  4, 'agi_magicnum',   '>I'),
    (4,  4, 'agi_versionnum', '>I'),
    (8,  4, 'agi_seqno',      '>I'),
    (12, 4, 'agi_length',     '>I'),
    (16, 4, 'agi_count',      '>I'),
    (20, 4, 'agi_root',       '>I'),
    (24, 4, 'agi_level',      '>I'),
    (28, 4, 'agi_freecount',  '>I'),
    (32, 4, 'agi_newino',     '>I'),
    (36, 4, 'agi_dirino',     '>I'),
]

_AGI_FIXED_SIZE = 40
_AGI_UNLINKED_OFF = 40
_AGI_UNLINKED_COUNT = 64
_AGI_SIZE = _AGI_FIXED_SIZE + _AGI_UNLINKED_COUNT * 4  # 296 bytes


def parse_agi(data):
    """Parse AGI header (296 bytes). Returns dict with 'agi_unlinked' list."""
    if len(data) < _AGI_SIZE:
        return None
    agi = {}
    for off, size, name, fmt in _AGI_FIELDS:
        agi[name] = struct.unpack(fmt, data[off:off + size])[0]

    # Unlinked inode hash table: 64 entries of 4 bytes each
    agi['agi_unlinked'] = []
    for i in range(_AGI_UNLINKED_COUNT):
        off = _AGI_UNLINKED_OFF + i * 4
        agi['agi_unlinked'].append(struct.unpack('>I', data[off:off + 4])[0])

    return agi


def pack_agi(agi):
    """Pack AGI dict to bytes. Returns sector-sized (512) buffer."""
    buf = bytearray(512)
    for off, size, name, fmt in _AGI_FIELDS:
        if name in agi:
            struct.pack_into(fmt, buf, off, agi[name])

    # Unlinked table
    unlinked = agi.get('agi_unlinked', [NULLAGBLOCK] * _AGI_UNLINKED_COUNT)
    for i in range(_AGI_UNLINKED_COUNT):
        off = _AGI_UNLINKED_OFF + i * 4
        val = unlinked[i] if i < len(unlinked) else NULLAGBLOCK
        struct.pack_into('>I', buf, off, val)

    return bytes(buf)


# ── Inode Core ──────────────────────────────────────────────────────

_INODE_CORE_FIELDS = [
    (0,  2, 'di_magic',     '>H'),
    (2,  2, 'di_mode',      '>H'),
    (4,  1, 'di_version',   '>B'),
    (5,  1, 'di_format',    '>B'),
    (6,  2, 'di_onlink',    '>H'),
    (8,  4, 'di_uid',       '>I'),
    (12, 4, 'di_gid',       '>I'),
    (16, 4, 'di_nlink',     '>I'),
    (20, 2, 'di_projid',    '>H'),
    # 22..31: pad (10 bytes)
    (32, 4, 'di_atime_sec',  '>i'),
    (36, 4, 'di_atime_nsec', '>i'),
    (40, 4, 'di_mtime_sec',  '>i'),
    (44, 4, 'di_mtime_nsec', '>i'),
    (48, 4, 'di_ctime_sec',  '>i'),
    (52, 4, 'di_ctime_nsec', '>i'),
    (56, 8, 'di_size',       '>q'),   # signed for size
    (64, 8, 'di_nblocks',    '>Q'),
    (72, 4, 'di_extsize',    '>I'),
    (76, 4, 'di_nextents',   '>I'),   # was >i in sgi_fs.py but spec is __uint32_t
    (80, 2, 'di_anextents',  '>H'),
    (82, 1, 'di_forkoff',    '>B'),
    (83, 1, 'di_aformat',    '>B'),
    (84, 4, 'di_dmevmask',   '>I'),
    (88, 2, 'di_dmstate',    '>H'),
    (90, 2, 'di_flags',      '>H'),
    (92, 4, 'di_gen',        '>I'),
]

_INODE_CORE_SIZE = 96


def parse_inode_core(data):
    """Parse the 96-byte inode core. Returns dict.

    Does NOT include data fork or _raw — caller adds those.
    """
    if len(data) < _INODE_CORE_SIZE:
        return None
    core = {}
    for off, size, name, fmt in _INODE_CORE_FIELDS:
        core[name] = struct.unpack(fmt, data[off:off + size])[0]
    # Pad bytes (for round-trip)
    core['_pad'] = data[22:32]
    return core


def pack_inode_core(core):
    """Pack inode core to 96 bytes."""
    buf = bytearray(96)
    for off, size, name, fmt in _INODE_CORE_FIELDS:
        if name in core:
            struct.pack_into(fmt, buf, off, core[name])
    # Pad
    pad = core.get('_pad', b'\x00' * 10)
    buf[22:32] = pad
    return bytes(buf)


# ── BMBT Record (Extent Map) ───────────────────────────────────────

def parse_bmbt_rec(data):
    """Parse a 16-byte packed XFS extent record.

    Returns (startoff, startblock, blockcount, flag).
    """
    l0, l1 = struct.unpack('>QQ', data[:16])
    flag       = (l0 >> 63) & 1
    startoff   = (l0 >> 9) & 0x3FFFFFFFFFFFFF   # 54 bits
    startblock = ((l0 & 0x1FF) << 43) | (l1 >> 21)  # 52 bits
    blockcount = l1 & 0x1FFFFF                    # 21 bits
    return (startoff, startblock, blockcount, flag)


def pack_bmbt_rec(startoff, startblock, blockcount, flag=0):
    """Pack an extent record to 16 bytes."""
    l0 = ((flag & 1) << 63) | ((startoff & 0x3FFFFFFFFFFFFF) << 9) | ((startblock >> 43) & 0x1FF)
    l1 = ((startblock & 0x7FFFFFFFFFF) << 21) | (blockcount & 0x1FFFFF)
    return struct.pack('>QQ', l0, l1)


# ── Alloc B+tree Record ────────────────────────────────────────────

def parse_alloc_rec(data):
    """Parse 8-byte alloc record. Returns (ar_startblock, ar_blockcount)."""
    return struct.unpack('>II', data[:8])


def pack_alloc_rec(startblock, blockcount):
    """Pack alloc record to 8 bytes."""
    return struct.pack('>II', startblock, blockcount)


# ── Inobt Record ───────────────────────────────────────────────────

def parse_inobt_rec(data):
    """Parse 16-byte inobt record.

    Returns dict: ir_startino, ir_freecount, ir_free.
    """
    ir_startino = struct.unpack('>I', data[0:4])[0]
    ir_freecount = struct.unpack('>i', data[4:8])[0]
    ir_free = struct.unpack('>Q', data[8:16])[0]
    return {
        'ir_startino': ir_startino,
        'ir_freecount': ir_freecount,
        'ir_free': ir_free,
    }


def pack_inobt_rec(rec):
    """Pack inobt record dict to 16 bytes."""
    return struct.pack('>iQ',
                       rec['ir_freecount'],
                       rec['ir_free'])


def pack_inobt_rec_full(rec):
    """Pack full inobt record (key + data) to 16 bytes."""
    return struct.pack('>IiQ',
                       rec['ir_startino'],
                       rec['ir_freecount'],
                       rec['ir_free'])


# ── B+tree Block Headers ───────────────────────────────────────────

def parse_btree_sblock(data):
    """Parse 16-byte short-form B+tree block header.

    Returns dict: bb_magic, bb_level, bb_numrecs, bb_leftsib, bb_rightsib.
    """
    if len(data) < XFS_BTREE_SBLOCK_SIZE:
        return None
    magic, level, numrecs, leftsib, rightsib = struct.unpack(
        '>IHHII', data[:16])
    return {
        'bb_magic': magic,
        'bb_level': level,
        'bb_numrecs': numrecs,
        'bb_leftsib': leftsib,
        'bb_rightsib': rightsib,
    }


def pack_btree_sblock(hdr):
    """Pack short-form B+tree header to 16 bytes."""
    return struct.pack('>IHHII',
                       hdr['bb_magic'],
                       hdr['bb_level'],
                       hdr['bb_numrecs'],
                       hdr['bb_leftsib'],
                       hdr['bb_rightsib'])


def parse_btree_lblock(data):
    """Parse 24-byte long-form B+tree block header.

    Returns dict: bb_magic, bb_level, bb_numrecs, bb_leftsib, bb_rightsib.
    """
    if len(data) < XFS_BTREE_LBLOCK_SIZE:
        return None
    magic, level, numrecs = struct.unpack('>IHH', data[0:8])
    leftsib, rightsib = struct.unpack('>QQ', data[8:24])
    return {
        'bb_magic': magic,
        'bb_level': level,
        'bb_numrecs': numrecs,
        'bb_leftsib': leftsib,
        'bb_rightsib': rightsib,
    }


def pack_btree_lblock(hdr):
    """Pack long-form B+tree header to 24 bytes."""
    return struct.pack('>IHHQQ',
                       hdr['bb_magic'],
                       hdr['bb_level'],
                       hdr['bb_numrecs'],
                       hdr['bb_leftsib'],
                       hdr['bb_rightsib'])


# ── BMDR Block (in-inode B+tree root) ──────────────────────────────

def parse_bmdr_block(data):
    """Parse 4-byte in-inode B+tree root header.

    Returns dict: bb_level, bb_numrecs.
    """
    if len(data) < XFS_BMDR_BLOCK_SIZE:
        return None
    level, numrecs = struct.unpack('>HH', data[:4])
    return {'bb_level': level, 'bb_numrecs': numrecs}


def pack_bmdr_block(hdr):
    """Pack in-inode B+tree root header to 4 bytes."""
    return struct.pack('>HH', hdr['bb_level'], hdr['bb_numrecs'])


# ── XFS Directory Hash ─────────────────────────────────────────────

def xfs_da_hashname(name):
    """Compute XFS directory name hash.

    Exact reimplementation of xfs_da_btree.c:1616 xfs_da_hashname().
    name: bytes or str (will be encoded as ascii).
    Returns uint32 hash.
    """
    if isinstance(name, str):
        name = name.encode('ascii')

    h = 0
    i = 0
    n = len(name)

    # Process 4 bytes at a time
    while n - i >= 4:
        h = ((name[i] << 21) ^ (name[i+1] << 14) ^
             (name[i+2] << 7) ^ name[i+3] ^
             _rotl32(h, 28))
        h &= 0xFFFFFFFF
        i += 4

    # Handle remaining bytes
    rem = n - i
    if rem == 3:
        h = ((name[i] << 14) ^ (name[i+1] << 7) ^ name[i+2] ^
             _rotl32(h, 21))
    elif rem == 2:
        h = ((name[i] << 7) ^ name[i+1] ^ _rotl32(h, 14))
    elif rem == 1:
        h = (name[i] ^ _rotl32(h, 7))

    return h & 0xFFFFFFFF


def _rotl32(x, n):
    """32-bit rotate left."""
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# ── Address Conversion Helpers ──────────────────────────────────────

def ino_to_agno(sb, ino):
    """Extract AG number from inode number."""
    return ino >> (sb['sb_agblklog'] + sb['sb_inopblog'])


def ino_to_agino(sb, ino):
    """Extract AG-relative inode number."""
    return ino & ((1 << (sb['sb_agblklog'] + sb['sb_inopblog'])) - 1)


def ino_to_offset(sb, ino, part_offset):
    """Convert XFS inode number to disk byte offset."""
    agblklog = sb['sb_agblklog']
    inopblog = sb['sb_inopblog']
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']
    inodesize = sb['sb_inodesize']

    agno = ino >> (agblklog + inopblog)
    agino = ino & ((1 << (agblklog + inopblog)) - 1)
    agbno = agino >> inopblog
    ino_slot = agino & ((1 << inopblog) - 1)

    phys_block = agno * agblocks + agbno
    return part_offset + phys_block * blocksize + ino_slot * inodesize


def fsblock_to_offset(sb, part_offset, fsblock):
    """Convert XFS filesystem block to disk byte offset.

    fsblock is encoded as (agno << agblklog) | agbno.
    """
    agblklog = sb['sb_agblklog']
    agblocks = sb['sb_agblocks']
    blocksize = sb['sb_blocksize']

    agno = fsblock >> agblklog
    agbno = fsblock & ((1 << agblklog) - 1)
    phys_block = agno * agblocks + agbno
    return part_offset + phys_block * blocksize


def agbno_to_fsblock(sb, agno, agbno):
    """Convert AG number + AG-relative block to filesystem block."""
    return (agno << sb['sb_agblklog']) | agbno


def fsblock_to_agno(sb, fsblock):
    """Extract AG number from filesystem block."""
    return fsblock >> sb['sb_agblklog']


def fsblock_to_agbno(sb, fsblock):
    """Extract AG-relative block from filesystem block."""
    return fsblock & ((1 << sb['sb_agblklog']) - 1)


def agino_to_ino(sb, agno, agino):
    """Convert AG number + AG-relative inode to full inode number."""
    return (agno << (sb['sb_agblklog'] + sb['sb_inopblog'])) | agino


def valid_fsblock(bno):
    """Check if a filesystem block number is valid (not null/sentinel)."""
    return bno != 0 and bno != NULLFSBLOCK and bno != 0xFFFFFFFFFFFFFFFF


def valid_agblock(bno):
    """Check if an AG-relative block number is valid."""
    return bno != 0 and bno != NULLAGBLOCK


def has_dirv2(sb):
    """Check if filesystem uses directory version 2 format."""
    return bool(sb['sb_versionnum'] & 0x2000)


def has_ftype(sb):
    """Check if filesystem has filetype in directory entries.

    Requires MOREBITSBIT (0x8000) in sb_versionnum and FTYPE (0x200)
    in sb_features2.
    """
    if not (sb['sb_versionnum'] & 0x8000):
        return False
    return bool(sb.get('sb_features2', 0) & 0x200)
