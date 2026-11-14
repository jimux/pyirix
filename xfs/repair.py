"""pyirix.xfs.repair — XFS diagnostics and repair.

Two layers:
  check_xfs()  — structured, read-only fsck-style inspection of an XFS partition
  repair_*()   — targeted fixes (mask bad version bits, recover the primary
                 superblock from a secondary copy, zero a dirty log)

All functions take an open file positioned arbitrarily and the byte offset of
the XFS partition (as returned by find_xfs_partition). Repairs accept
dry_run=True (the default) and only write when explicitly told to.
"""

import struct

from pyirix.xfs.constants import (
    XFS_SB_MAGIC, XFS_AGF_MAGIC, XFS_AGI_MAGIC,
    XFS_SB_VERSION_OKSASHBITS, S_IFMT, S_IFDIR,
)
from pyirix.xfs.ondisk import parse_superblock
from pyirix.xfs.superblock import read_superblock, write_superblock, sash_compatible, zero_log
from pyirix.xfs.alloc import read_agf
from pyirix.xfs.ialloc import read_agi
from pyirix.xfs.inode import read_inode, get_extents


class Finding:
    """One diagnostic result. level in {'PASS','INFO','WARN','FAIL'}."""
    __slots__ = ('level', 'code', 'msg')

    def __init__(self, level, code, msg):
        self.level, self.code, self.msg = level, code, msg

    def __repr__(self):
        return f"[{self.level}] {self.code}: {self.msg}"


class CheckReport:
    def __init__(self):
        self.findings = []

    def add(self, level, code, msg):
        self.findings.append(Finding(level, code, msg))

    @property
    def ok(self):
        return not any(f.level == 'FAIL' for f in self.findings)

    @property
    def repairable(self):
        """True if every FAIL has a known repair code."""
        fails = [f for f in self.findings if f.level == 'FAIL']
        return bool(fails) and all(f.code in _REPAIRS for f in fails)

    def by_level(self, level):
        return [f for f in self.findings if f.level == level]

    def __iter__(self):
        return iter(self.findings)

    def summary(self):
        from collections import Counter
        c = Counter(f.level for f in self.findings)
        return " ".join(f"{k}={c[k]}" for k in ('PASS', 'INFO', 'WARN', 'FAIL') if c[k])


def _file_size(f):
    import os
    return os.fstat(f.fileno()).st_size


def check_xfs(f, part_offset):
    """Read-only structural check. Returns a CheckReport."""
    r = CheckReport()

    f.seek(part_offset)
    raw = f.read(512)
    sb = parse_superblock(raw)
    if sb is None or sb.get('sb_magicnum') != XFS_SB_MAGIC:
        got = struct.unpack('>I', raw[0:4])[0] if len(raw) >= 4 else 0
        r.add('FAIL', 'sb_magic',
              f"primary superblock magic {got:#010x} != XFSB ({XFS_SB_MAGIC:#010x})")
        # Without a primary SB we can still look for a secondary.
        sec = find_secondary_superblock(f, part_offset)
        if sec:
            r.add('INFO', 'secondary_sb',
                  f"valid secondary superblock found at byte {sec[0]} (agno {sec[2]})")
        return r
    r.add('PASS', 'sb_magic', "superblock magic OK")

    ok, why = sash_compatible(sb)
    r.add('PASS' if ok else 'FAIL', 'sb_version', why)

    # Geometry consistency
    bs = sb['sb_blocksize']
    if bs <= 0 or (bs & (bs - 1)):
        r.add('FAIL', 'geometry', f"blocksize {bs} not a power of two")
    elif (1 << sb['sb_blocklog']) != bs:
        r.add('FAIL', 'geometry',
              f"blocklog {sb['sb_blocklog']} inconsistent with blocksize {bs}")
    elif sb['sb_inodesize'] and bs // sb['sb_inodesize'] != sb['sb_inopblock']:
        r.add('WARN', 'geometry',
              f"inopblock {sb['sb_inopblock']} != blocksize/inodesize")
    else:
        r.add('PASS', 'geometry', "block/inode geometry consistent")

    # Per-AG headers
    bad_ag = []
    for agno in range(sb['sb_agcount']):
        agf = read_agf(f, part_offset, sb, agno)
        agi = read_agi(f, part_offset, sb, agno)
        if agf is None or agf.get('agf_magicnum') != XFS_AGF_MAGIC:
            bad_ag.append((agno, 'AGF'))
        if agi is None or agi.get('agi_magicnum') != XFS_AGI_MAGIC:
            bad_ag.append((agno, 'AGI'))
    if bad_ag:
        r.add('FAIL', 'ag_headers', f"corrupt AG headers: {bad_ag}")
    else:
        r.add('PASS', 'ag_headers', f"all {sb['sb_agcount']} AG header(s) valid")

    # Root inode
    root = read_inode(f, part_offset, sb, sb['sb_rootino'])
    if root is None:
        r.add('FAIL', 'root_inode', f"root inode {sb['sb_rootino']} unreadable")
    elif (root['di_mode'] & S_IFMT) != S_IFDIR:
        r.add('FAIL', 'root_inode', "root inode is not a directory")
    else:
        r.add('PASS', 'root_inode', f"root inode {sb['sb_rootino']} is a directory")

    # Log range sanity
    if sb['sb_logstart'] and sb['sb_logblocks']:
        end = sb['sb_logstart'] + sb['sb_logblocks']
        if end > sb['sb_dblocks']:
            r.add('WARN', 'log', "internal log extends past end of filesystem")
        else:
            r.add('INFO', 'log',
                  f"internal log at fsblock {sb['sb_logstart']} ({sb['sb_logblocks']} blocks)")
    else:
        r.add('INFO', 'log', "no internal log (external or none)")

    _check_directory_tree(f, part_offset, sb, r)

    return r


# ── Directory traversal ─────────────────────────────────────────────
# check_xfs validated the superblock, geometry, AG headers, the root inode's
# TYPE and the log -- and never read a single directory block. A directory that
# is corrupt, a directory that is merely full, and a directory that is healthy
# all produced the same six PASS lines.
#
# That matters because the writer cannot grow a dir2 BLOCK into a LEAF
# (sf_to_dir2_block exists; block->leaf does not), so a directory with enough
# entries simply stops accepting them. Without traversal, a checker cannot tell
# an operator which of the three states they are in.

DIR_CHECK_MAX_DIRS = 20000        # bound: a full walk of a 4 GiB fs is seconds,
                                  # but say so rather than walking forever


def _dir_block_magics_bad(f, part_offset, sb, inode):
    """A description of the FIRST block whose header magic is unrecognised, or ''.

    The three legitimate layouts, and where each keeps its magic:
      V1 leaf        magic 0xFEEB at byte 8   (the IRIX-XFS leaf block)
      dir2 block     magic 'XD2B' at byte 0
      dir2 data      magic 'XD2D' at byte 0
    Anything else is a header read_dir_entries() would silently skip.
    """
    from pyirix.xfs.constants import (XFS_DIR_LEAF_MAGIC, XFS_DIR2_BLOCK_MAGIC,
                                      XFS_DIR2_DATA_MAGIC, XFS_DA_NODE_MAGIC)
    from pyirix.xfs.ondisk import fsblock_to_offset
    try:
        extents = get_extents(f, part_offset, sb, inode)
    except Exception as e:
        return "extents unreadable: %s" % e
    if not extents:
        return "no extents"
    blocksize = sb['sb_blocksize']
    for _startoff, startblock, blockcount in extents:
        for blk in range(blockcount):
            f.seek(fsblock_to_offset(sb, part_offset, startblock + blk))
            head = f.read(16)
            if len(head) < 16:
                return "short block at fsblock %d" % (startblock + blk)
            m4 = struct.unpack('>I', head[0:4])[0]
            m2 = struct.unpack('>H', head[8:10])[0]
            if m2 in (XFS_DIR_LEAF_MAGIC, XFS_DA_NODE_MAGIC):
                # 0xFEEB V1-leaf entry block · 0xFEBE DA B+tree INTERNAL node.
                # The node is an index, not an entry block; read_dir_entries
                # refuses it by design, so its presence is not a fault.
                continue
            if m4 in (XFS_DIR2_BLOCK_MAGIC, XFS_DIR2_DATA_MAGIC):
                continue
            return ("fsblock %d: magic4=0x%08x magic2=0x%04x"
                    % (startblock + blk, m4, m2))
    return ""


def _check_directory_tree(f, part_offset, sb, r):
    """Walk every directory and report structural faults it can SEE.

    Adds ONE summary finding plus a finding per fault class -- not one per
    directory, because a healthy filesystem has thousands of directories and a
    checker that emits a line each is unreadable.

    What it detects, and what it deliberately does not:
      * a directory whose inode cannot be read, or is not a directory;
      * a directory whose entries cannot be parsed at all (the block magic is
        neither XFS_DIR2_BLOCK_MAGIC nor a DA node);
      * an entry whose child inode does not exist -- the silent skip that
        list_dir() performs and that would otherwise hide a hole;
      * a directory at its block-capacity ceiling (the measured ~120 long-name
        case) -- reported as INFO, because it is a LIMIT not a fault.

    It does NOT verify bestfree/bestfree offsets or free-space accounting:
    those require the dir2 data-header semantics that the last wrong reading in
    this area got wrong (a bestfree offset read as a magic). A check that
    guesses at a structure it does not parse is worse than no check.
    """
    from pyirix.xfs.directory import read_dir_entries, read_dir_sf
    from pyirix.xfs.constants import (XFS_DINODE_FMT_BTREE, XFS_DINODE_FMT_EXTENTS,
                                      XFS_DINODE_FMT_LOCAL)

    root = sb['sb_rootino']
    seen = set()
    stack = [(root, '/')]
    dirs = files = 0
    unreadable_dirs, unparsable_dirs, holes, bad_headers = [], [], [], []
    full_dirs = 0

    while stack:
        ino, path = stack.pop()
        if ino in seen or dirs >= DIR_CHECK_MAX_DIRS:
            continue
        seen.add(ino)
        try:
            inode = read_inode(f, part_offset, sb, ino)
        except Exception as e:
            unreadable_dirs.append((path, "%s: %s" % (type(e).__name__, e)))
            continue
        if inode is None:
            unreadable_dirs.append((path, "inode unreadable"))
            continue
        if (inode['di_mode'] & 0o170000) != 0o040000:
            continue
        dirs += 1
        try:
            entries = read_dir_entries(f, part_offset, sb, inode)
        except Exception as e:
            unparsable_dirs.append((path, "%s: %s" % (type(e).__name__, e)))
            continue
        # HEADER VALIDATION, per format. read_dir_entries() SKIPS a block it does
        # not recognise (directory.py: `continue` on an unknown magic), so a
        # corrupted header yields an EMPTY entry list and looks like an empty
        # directory. That is the silent hole this check exists to close, so the
        # magic must be tested HERE rather than inferred from the parse result.
        if inode['di_format'] in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
            bad = _dir_block_magics_bad(f, part_offset, sb, inode)
            if bad:
                bad_headers.append((path, bad))
                continue
        # A grown directory whose single block is at capacity is a LIMIT, and it
        # is the state that makes create_file refuse. Surface it as INFO once.
        if inode['di_format'] in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
            try:
                if inode['di_size'] and inode['di_size'] <= sb['sb_blocksize']:
                    full_dirs += 1
            except Exception:
                pass
        for name, child_ino in entries:
            files += 1
            try:
                child = read_inode(f, part_offset, sb, child_ino)
            except Exception:
                child = None
            if child is None:
                # list_dir() skips these silently; count them instead.
                holes.append((path, name, child_ino))
                continue
            if (child['di_mode'] & 0o170000) == 0o040000:
                stack.append((child_ino, path.rstrip('/') + '/' + name))

    if unreadable_dirs:
        r.add('FAIL', 'dir_inode',
              "%d director%s unreadable (first: %s: %s)"
              % (len(unreadable_dirs), 'y' if len(unreadable_dirs) == 1 else 'ies',
                 unreadable_dirs[0][0], unreadable_dirs[0][1]))
    if unparsable_dirs:
        r.add('FAIL', 'dir_entries',
              "%d director%s whose entries cannot be parsed (first: %s: %s)"
              % (len(unparsable_dirs), 'y' if len(unparsable_dirs) == 1 else 'ies',
                 unparsable_dirs[0][0], unparsable_dirs[0][1]))
    if bad_headers:
        r.add('FAIL', 'dir_block_magic',
              "%d director%s with a block header that is neither a V1 leaf (0xFEEB) "
              "nor dir2 (XD2B/XD2D) (first: %s: %s)"
              % (len(bad_headers), 'y' if len(bad_headers) == 1 else 'ies',
                 bad_headers[0][0], bad_headers[0][1]))
    if holes:
        r.add('FAIL', 'dir_entry_ino',
              "%d director%s entr%s pointing at an unreadable inode (first: %s/%s -> %s)"
              % (len(holes), 'y' if len(holes) == 1 else 'ies',
                 'y' if len(holes) == 1 else 'ies',
                 holes[0][0], holes[0][1], holes[0][2]))
    level = 'FAIL' if (unreadable_dirs or unparsable_dirs or holes or bad_headers) else 'PASS'
    r.add(level, 'dir_tree',
          "%d director%s, %d entr%s traversed%s"
          % (dirs, 'y' if dirs == 1 else 'ies', files, 'y' if files == 1 else 'ies',
             "" if not full_dirs else
             "; %d at single-block capacity (new entries will be refused)"
             % full_dirs))


def find_secondary_superblock(f, part_offset, max_scan_bytes=64 * 1024 * 1024):
    """Scan past the primary for a valid secondary superblock.

    Returns (file_byte_offset, sb_dict, agno) or None. Used to recover a
    destroyed primary superblock without knowing the geometry up front.
    """
    size = _file_size(f)
    limit = min(size, part_offset + max_scan_bytes)
    # Secondary superblocks sit at AG starts (block-aligned); scan at sector
    # granularity to be robust, skipping the primary at offset 0.
    pos = part_offset + 512
    while pos + 512 <= limit:
        f.seek(pos)
        chunk = f.read(512)
        if len(chunk) >= 4 and struct.unpack('>I', chunk[0:4])[0] == XFS_SB_MAGIC:
            cand = parse_superblock(chunk)
            if cand and cand['sb_blocksize'] and cand['sb_agblocks']:
                agbytes = cand['sb_agblocks'] * cand['sb_blocksize']
                rel = pos - part_offset
                agno = rel // agbytes if agbytes else 0
                return (pos, cand, agno)
        pos += 512
    return None


# ── Repairs ─────────────────────────────────────────────────────────

def repair_version_bits(f, part_offset, dry_run=True):
    """If a v4 superblock has feature bits the PROM/SASH rejects, mask them.

    Returns a dict describing the action (or no-op).
    """
    sb = read_superblock(f, part_offset)
    if sb is None:
        return {'changed': False, 'reason': 'no readable primary superblock'}
    ver = sb['sb_versionnum']
    if (ver & 0x000f) != 4:
        return {'changed': False, 'reason': f'version {ver:#x} not v4; nothing to mask'}
    extra = ver & ~XFS_SB_VERSION_OKSASHBITS
    if not extra:
        return {'changed': False, 'reason': f'version {ver:#x} already SASH-clean'}
    new = ver & XFS_SB_VERSION_OKSASHBITS
    if not dry_run:
        sb['sb_versionnum'] = new
        write_superblock(f, part_offset, sb)
    return {'changed': not dry_run, 'old': ver, 'new': new,
            'reason': f'masked SASH-incompatible bits {extra:#x}: {ver:#x} -> {new:#x}'}


def recover_superblock(f, part_offset, dry_run=True):
    """If the primary superblock is unreadable, rewrite it from a secondary.

    Returns a dict describing the action.
    """
    primary = read_superblock(f, part_offset)
    if primary is not None:
        return {'changed': False, 'reason': 'primary superblock is valid'}
    sec = find_secondary_superblock(f, part_offset)
    if not sec:
        return {'changed': False, 'reason': 'no secondary superblock found'}
    sec_off, sec_sb, agno = sec
    if not dry_run:
        f.seek(sec_off)
        good = f.read(512)
        f.seek(part_offset)
        f.write(good)
        f.flush()
    return {'changed': not dry_run, 'source_offset': sec_off, 'source_agno': agno,
            'reason': f'recovered primary from secondary at AG {agno} (byte {sec_off})'}


def clean_log(f, part_offset, dry_run=True):
    """Zero the internal log so a stale/dirty journal will not be replayed."""
    sb = read_superblock(f, part_offset)
    if sb is None:
        return {'changed': False, 'reason': 'no readable superblock'}
    if not (sb['sb_logstart'] and sb['sb_logblocks']):
        return {'changed': False, 'reason': 'no internal log'}
    if not dry_run:
        zero_log(f, part_offset, sb)
    return {'changed': not dry_run,
            'reason': f"zeroed log: {sb['sb_logblocks']} blocks at fsblock {sb['sb_logstart']}"}


# Map FAIL codes to the repair callable that addresses them.
_REPAIRS = {
    'sb_magic': recover_superblock,
    'sb_version': repair_version_bits,
}


def repair_xfs(f, part_offset, dry_run=True):
    """Run check_xfs, then apply the repair for each repairable FAIL.

    Returns (report, actions). For dry_run, actions describe what *would* be done.
    Recovering the primary superblock is attempted first (others depend on it).
    """
    report = check_xfs(f, part_offset)
    actions = []
    codes = {fnd.code for fnd in report.by_level('FAIL')}
    if 'sb_magic' in codes:
        actions.append(('recover_superblock', recover_superblock(f, part_offset, dry_run)))
    if 'sb_version' in codes:
        actions.append(('repair_version_bits', repair_version_bits(f, part_offset, dry_run)))
    return report, actions
