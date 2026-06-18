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
from pyirix.xfs.inode import read_inode


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

    return r


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
