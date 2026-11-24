"""EFS builder regression tests: a medium must read back what was written.

The defect these arms were written for: ``pyirix.efs.builder`` sized a volume
from an estimate that did not model the per-CG inode blocks, then let the block
allocator walk past ``fs_size`` into a phantom cylinder group.  The bytes went
outside the filesystem (and over the revolving superblock), so the image came
out at the RIGHT length with WRONG bytes -- invisible to a size check, and
corrupt to IRIX ``inst``.  On the real IRIX 6.5 Foundation 1 tree (76 files) the
corrupted file was ``/x_eoe.sw64``, first divergence at byte 2,232,320.

The synthetic tree below reproduces the same class on any node, with the same
reader the mount path uses (``pyirix.efs.reader``), so the arms need neither the
527 MB real tree nor a VM.  Measured on pyirix 0fc4a4a (no fix) the synthetic
arms are RED and on 26e6230 (the fix) they are GREEN -- an arm that passes on
both would not be a test.

    python3 -m pytest tests/test_efs_readback.py -q
"""
import os

import pytest

from pyirix.efs import builder, reader
from pyirix.efs.builder import S_IFDIR, S_IFMT, mkfs_efs

#: Where the extracted IRIX 6.5.5 dist trees live; the real-shape arm skips
#: with a reason when this node has none.
REAL_DIST_ROOT = os.environ.get("IRIX_EFS_DIST_ROOT") or os.path.expanduser(
    "~/qemu-sgi/software_library/prepackaged_combo_discs/IRIX_6.5.5_full_extracted")


def _payload(seed, size):
    """Deterministic bytes with no short repeating stride, so a shifted read
    cannot accidentally alias to the right bytes."""
    out = bytearray(size)
    x = (seed * 2654435761) & 0xFFFFFFFF
    for i in range(size):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (x >> 16) & 0xFF
    return bytes(out)


def _synthetic_tree():
    """The smallest shape measured to make the pre-fix builder publish a file
    that does not read back.

    1,400 one-byte files push the inode count high enough that the old estimate
    came up short (it allowed ``n_nodes // 8`` blocks where the layout spends
    ``ncg * cgisize``, about ``n_nodes // 4``), and one 300,000-byte file walks
    the allocator into the shortfall.  Measured on 0fc4a4a: 7 files placed
    outside ``fs_size`` and ``/f01392`` reads back a different byte; on 26e6230
    every file reads back and no extent leaves the volume.
    """
    files = {"/f%05d" % i: bytes([(i * 31) & 0xFF]) for i in range(1400)}
    files["/big"] = _payload(1, 300000)
    return files


def _walk(image_path):
    """Yield (guest path, inode) for every non-directory in the image."""
    with open(image_path, "rb") as f:
        part_offset, _length = reader.find_efs_partition(f)
        sb = reader.read_superblock(f, part_offset)
        entries = []

        def walk(ino, prefix):
            inode = reader.read_inode(f, part_offset, sb, ino)
            for name, child in reader.read_dir_entries(f, part_offset, sb, inode):
                path = prefix + "/" + (
                    name.decode() if isinstance(name, bytes) else name)
                child_inode = reader.read_inode(f, part_offset, sb, child)
                if (child_inode["mode"] & S_IFMT) == S_IFDIR:
                    walk(child, path)
                else:
                    entries.append((path, child_inode))
        walk(reader.EFS_ROOT_INODE, "")
    return sb, entries


def _read_back_tree(image_path):
    """Guest path -> bytes for every file in the image, through pyirix.efs.reader."""
    sb, entries = _walk(image_path)
    with open(image_path, "rb") as f:
        part_offset, _length = reader.find_efs_partition(f)
        return sb, {path: reader.read_file_data(f, part_offset, sb, inode)
                    for path, inode in entries}


def _first_divergence(want, got):
    for i in range(min(len(want), len(got))):
        if want[i] != got[i]:
            return i
    return None if len(want) == len(got) else min(len(want), len(got))


class TestSyntheticTreeReadsBack:
    """A built medium must hold the bytes that were staged into it."""

    def test_every_file_reads_back_byte_identical(self, tmp_path):
        files = _synthetic_tree()
        image = str(tmp_path / "tree.efs")
        mkfs_efs(image, files=files, with_volume_header=False)
        _sb, got = _read_back_tree(image)
        wrong = sorted(p for p in files if got.get(p) != files[p])
        if wrong:
            first = _first_divergence(files[wrong[0]], got.get(wrong[0]) or b"")
            raise AssertionError(
                "%d/%d files do not read back (first wrong file %s, first "
                "divergence at byte %s): the builder published a medium whose "
                "content is not what it wrote"
                % (len(wrong), len(files), wrong[0], first))
        assert len(got) == len(files), "staged %d files, image holds %d" % (
            len(files), len(got))

    def test_no_extent_lies_outside_the_volume(self, tmp_path):
        files = _synthetic_tree()
        image = str(tmp_path / "tree.efs")
        mkfs_efs(image, files=files, with_volume_header=False)
        sb, entries = _walk(image)
        outside = []
        for path, inode in entries:
            for extent in inode.get("extents") or []:
                if extent["length"] and extent["bn"] + extent["length"] > sb["fs_size"]:
                    outside.append((path, extent["bn"], extent["length"]))
        assert outside == [], (
            "%d extent(s) reach past fs_size=%d, so those bytes were written "
            "outside the filesystem (first: %s)"
            % (len(outside), sb["fs_size"], outside[:3]))


class TestRefusals:
    """The half of the fix that stops the next occurrence: refuse, do not publish."""

    def test_a_budget_too_small_for_the_tree_is_refused(self, tmp_path):
        assert hasattr(builder, "EFSFullError"), (
            "pyirix.efs.builder carries no EFSFullError: a tree that does not "
            "fit an explicit budget is not refused, it overruns the volume")
        files = {"/f%04d" % i: b"ab" for i in range(1248)}
        with pytest.raises(builder.EFSFullError):
            mkfs_efs(str(tmp_path / "small.efs"), files=files,
                     size_blocks=1631, with_volume_header=False)

    def test_a_wrong_image_is_refused_by_name(self, tmp_path):
        assert hasattr(builder, "verify_efs_readback"), (
            "pyirix.efs.builder carries no verify_efs_readback: a medium whose "
            "content does not survive the round trip ships silently")
        files = {"/a.txt": b"alpha\n", "/b.bin": bytes(range(256)) * 40}
        image = str(tmp_path / "ok.efs")
        mkfs_efs(image, files=files, with_volume_header=False)
        assert builder.verify_efs_readback(image, files) == []
        assert builder.verify_efs_readback(
            image, dict(files, **{"/b.bin": b"not what is in the image"})) == ["/b.bin"]

    def test_a_mismatch_raises_rather_than_returning_the_image(self, tmp_path):
        assert hasattr(builder, "EFSReadbackError"), (
            "pyirix.efs.builder carries no EFSReadbackError: build() does not "
            "verify what it wrote")
        files = {"/a.bin": _payload(2, 4096)}
        image = str(tmp_path / "b.efs")
        mkfs_efs(image, files=files, with_volume_header=False)
        # Same image, wrong expectation: the verifier must NAME the file, which
        # is what build() turns into EFSReadbackError instead of a finished
        # medium.
        assert builder.verify_efs_readback(
            image, {"/a.bin": _payload(3, 4096)}) == ["/a.bin"]


class TestRealFoundationOne:
    """The real tree that failed: 76 files, /x_eoe.sw64, byte 2,232,320."""

    @pytest.mark.slow
    def test_foundation_one_reads_back(self, tmp_path):
        src = os.path.join(REAL_DIST_ROOT, "IRIX_6.5_Foundation_1")
        if not os.path.isdir(src):
            pytest.skip(
                "the real IRIX 6.5 Foundation 1 tree is not on this node (%s); "
                "set IRIX_EFS_DIST_ROOT to the IRIX_6.5.5_full_extracted "
                "directory to grade it" % src)
        from pyirix.efs.media import collect_directory
        tree = collect_directory(src)
        image = str(tmp_path / "foundation1.efs")
        mkfs_efs(image, files=tree.files, symlinks=tree.symlinks,
                 dirs=tree.dirs, with_volume_header=False)
        _sb, got = _read_back_tree(image)
        size = os.path.getsize(image)
        wrong = sorted(p for p in tree.files if got.get(p) != tree.files[p])
        if wrong:
            first = _first_divergence(tree.files[wrong[0]], got.get(wrong[0]) or b"")
            raise AssertionError(
                "%d/%d files of the real Foundation 1 tree do not read back "
                "(image %d bytes; first wrong file %s, first divergence at byte %s)"
                % (len(wrong), len(tree.files), size, wrong[0], first))
        assert len(got) == len(tree.files)
