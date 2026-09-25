"""Non-blind disk-integrity audit: compare a candidate image against a golden.

Why this exists (and why ``xfs_scan`` is not enough): a filesystem can lose
metadata *structures* while every header that describes them stays valid. The
AG headers, the superblock, and the geometry all pass — so a structural scan
reports 6 PASS / 0 FAIL — while the inode clusters and free-space B-trees the
headers point at are gone. That is invisible to any check that only reads
headers.

Measured instance (2026-09-11): a QEMU-produced Indy disk had **8 contiguous
512KB blocks (4MB) of AG4 entirely zeroed** where the golden held live inode
clusters (``IN`` magic), inode cores, and free-space B-tree roots
(``ABTB``/``0xfeedbabe``). AG4's own superblock copy was byte-identical to the
golden, so ``xfs_scan`` passed it. Both MAME's IRIX and a stock IRIX kernel
rejected the disk at root mount; the cause was an unclean shutdown that lost
metadata the journal never recorded.

The reliable check is a block-by-block comparison restricted to blocks whose
*golden* content is an XFS structure. Zeroed file-data blocks are ordinary
guest churn; zeroed *metadata* blocks are data loss.
"""
from .image import open_disk_image, find_xfs_partition

#: Byte signatures that identify an XFS metadata structure at the start of a block.
XFS_STRUCTURE_SIGNATURES = (
    (b'XFSB', 'superblock'),
    (b'XAGF', 'AG free-space header'),
    (b'XAGI', 'AG inode header'),
    (b'ABTB', 'free-space B-tree root'),
    (b'ABTC', 'free-space by-count B-tree'),
    (b'IABT', 'inode B-tree root'),
    (b'IN  ', 'inode core'),
    (bytes.fromhex('feedbabe'), 'free-space B-tree root (v4)'),
)

#: The comparison granularity. 512KB matches the bisect blocks used in the
#: investigation that found this defect; any power-of-two multiple of the fs
#: block size works.
COMPARE_BLOCK = 512 * 1024


def _structure_at(block):
    """Return the description of an XFS structure in this block, or None."""
    head = block[:4096]
    for sig, name in XFS_STRUCTURE_SIGNATURES:
        if sig in head:
            return name
    return None


def audit_against_golden(candidate, golden):
    """Compare two images; report XFS structures present in ``golden`` but zeroed
    in ``candidate``.

    Both may be raw or qcow2 (anything :func:`open_disk_image` accepts). Returns
    a dict::

        {structures_in_golden, structures_lost, lost_blocks, max_zero_run,
         verdict, lost_detail}

    ``verdict`` is ``'CLEAN'`` when no structure was lost. ``lost_detail`` is a
    list of ``(block_index, byte_offset, structure_name, golden_nonzero_bytes)``.
    """
    def _blocks(path):
        """Yield 512KB blocks from the XFS partition of ``path``."""
        with open_disk_image(path) as f:
            part = find_xfs_partition(f)
            if part is None:
                raise ValueError(f"no XFS partition in {path}")
            base = part[0]
            f.seek(base)
            while True:
                b = f.read(COMPARE_BLOCK)
                if not b:
                    break
                yield b

    c_iter = _blocks(candidate)

    structures = lost = 0
    run = longest = 0
    detail = []
    idx = 0
    for gb in _blocks(golden):
        cb = next(c_iter, None)
        if cb is None:
            break
        g_has_data = any(gb)
        c_is_zero = not any(cb)
        if g_has_data and c_is_zero:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
        name = _structure_at(gb)
        if name:
            structures += 1
            if c_is_zero:
                lost += 1
                detail.append((idx, idx * COMPARE_BLOCK, name,
                               sum(1 for x in gb if x)))
        idx += 1

    return {
        'structures_in_golden': structures,
        'structures_lost': lost,
        'lost_blocks': [d[0] for d in detail],
        'max_zero_run': longest,
        'verdict': 'CLEAN' if lost == 0 else 'STRUCTURES LOST',
        'lost_detail': detail,
    }
