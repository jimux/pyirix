#!/usr/bin/env python3
"""Walk an IRIX install medium and pull out every inst/tardist item.

Takes an ISO9660 image, an SGI EFS disk/CD image, or an already-extracted
directory, and finds every `.idb` manifest, `pd001` spec file, and `.tardist`
bundle in it -- at any depth, regardless of whether the CD calls its package
directory `dist/`, `install/`, or something nested (SGI media is not
consistent about this; see `pyirix/docs/dist.md` and the layout notes in
`pkg_analyzer.EFSImageScanner`).

By SGI packaging convention a product's `.idb` always lives in the same
directory as the `.sw`/`.man`/... archives and spec file it describes (see
`pyirix/docs/dist.md`), so "walk it and find inst/tardist items" reduces to:
any directory containing an `.idb` is a product directory, and every file
in that directory is either the `.idb` itself, an archive one of the idb's
entries points at (`archive.archive_of_entry`), a `pd001` spec file, or
something incidental (README, checksum stub, ...) we leave alone.

Metadata (`.idb`, spec) is parsed and written as JSON, preserving the file's
path relative to the image root (`source_image_path`) so provenance survives
even though the working extraction happens in a throwaway staging directory.
Data archives are unpacked file-by-file via `pyirix.dist.archive.extract_product`
(which already handles multi-archive products and idbs with no `off()`
tokens); each extracted file's install path, subsystem, and content hash are
recorded in a per-product JSON manifest.

`.tardist` files (a tar bundling one product's idb+archives+spec) are
unpacked to a scratch directory and processed the same way, with their
image-relative members' paths prefixed `<tardist path>!<member>` so a file's
lineage back to the original image is never lost.

**Retaining extracted content is optional.** By default the extracted files
are kept under `data/`. With `retain_extractions=False` (`--no-retain-
extractions`) every file is still extracted and hashed, but the content is
discarded right after hashing -- the corpus keeps only JSON (metadata +
per-file hashes), which is a small fraction of the size. `validate_output`
handles both: it hash-checks retained copies where they exist, and for
non-retained entries re-derives the bytes straight out of the source image's
archive (via the recorded archive/offset/size) and checks those. So a
metadata-only corpus is still fully verifiable against its source media,
and anything needed later can be re-extracted on demand with
`pyirix.dist.archive.extract_product`.

CLI:
    python -m pyirix.dist.media_walker IRIX_6.5_Foundation_1.img -o out/foundation1
    python -m pyirix.dist.media_walker "Some Demo.iso" -o out/demo --hash md5
    python -m pyirix.dist.media_walker already_extracted_dir/ -o out/x --keep-staging
    # metadata + hashes only (no extracted content kept):
    python -m pyirix.dist.media_walker Foundation_1.img -o out/f1 --no-retain-extractions
    # re-verify a previous run (works with or without retained content):
    python -m pyirix.dist.media_walker Foundation_1.img -o out/f1 --validate
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from pyirix.dist.archive import (
    _reconstruct_offsets,
    archive_of_entry,
    extract_one,
    extract_product,
    resolve_archive,
)
from pyirix.dist.idb import IDBEntry, parse_idb
from pyirix.dist.parser import parse_spec
from pyirix.efs.extract import extract_efs
from pyirix.iso.extract import extract_recursive as iso_extract_recursive
from pyirix.iso.extract import is_iso9660

DEFAULT_HASH = "sha256"
SPEC_MAGIC = b"pd001"
SPEC_SNIFF_MAX_SIZE = 2_000_000   # spec files are small; skip sniffing huge files


# ── source detection / staging ────────────────────────────────────────────


# Whole-file compression wrappers, detected by magic (NOT by extension --
# real media is littered with `.image`, `.ISO`, `.cdr` and other spellings).
_COMPRESSION_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x9d", "compress"),   # Unix .Z (LZW) -- e.g. fsn.tar.Z
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),    # matches RAR4 (Rar!\\x1a\\x07\\x00) and RAR5
)
MAX_STAGE_DEPTH = 4   # e.g. .tar.gz -> tar -> ... ; guards pathological nesting

# A raw CD image stores whole sectors (2352 or 2448 bytes) rather than the
# 2048-byte user-data stream an .iso holds. Sector 0 of such an image begins
# with the 12-byte sector sync pattern (00 ff*10 00). Alcohol 120% `.mdf`,
# Nero `.nrg` dumps, and `.bin/.cue` CDDA dumps are all this shape.
_RAW_CD_SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
_RAW_CD_SECTOR_SIZES = (2048, 2324, 2336, 2352, 2448)
# SGI disklabel / volume-header magic at byte 0 of an EFS data track.
_SGI_VOLHDR_MAGIC = b"\x0b\xe5\xa9\x41"   # 0x0be5a941


def _compression_of(path: Path) -> Optional[str]:
    """Name of the whole-file compression wrapping `path`, or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    for magic, name in _COMPRESSION_MAGIC:
        if head.startswith(magic):
            return name
    return None


def _raw_cd_sector_size(path: Path) -> Optional[int]:
    """Sector size (2048..2448) if `path` is a raw-CD sector dump, else None.

    A raw dump opens with the 12-byte sector-sync pattern and repeats it at
    every sector boundary, so the sector size is found by locating the next
    boundaries where the sync recurs. This key is format-agnostic: it works
    for EFS discs too (SGI install CDs are EFS and carry no ISO9660 "CD001"
    PVD, which the old landmark-based probe wrongly required). A "CD001"
    fallback handles dumps that sync only their first sector (e.g. hand-built
    fixtures). Only the first megabyte is scanned.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read(1 << 20)
    except OSError:
        return None
    if not blob.startswith(_RAW_CD_SYNC):
        return None
    # Primary signal: the sync pattern recurs at each sector boundary.
    for ss in (2324, 2336, 2352, 2448):
        if all(blob[k * ss:k * ss + 12] == _RAW_CD_SYNC for k in (1, 2, 3)):
            return ss
    # Fallback: ISO9660 Primary Volume Descriptor in sector 16, at byte 1 of
    # that sector's user data. "CD001" is preceded by the 0x01 descriptor-type
    # byte and (for Mode 1) 16 bytes of sync+header. Determine the user-data
    # offset from the first sector's mode byte (sector[15]: 0x01 Mode 1 -> 16,
    # 0x02 Mode 2 -> 24).
    idx = blob.find(b"CD001")
    if idx < 0:
        return None
    mode = blob[15]
    user_off = 16 if mode != 0x02 else 24
    sector_start = idx - 1 - user_off
    if sector_start % 16 != 0:
        return None
    ss = sector_start // 16
    return ss if ss in _RAW_CD_SECTOR_SIZES else None


def _raw_cd_to_iso(path: Path, dest: Path) -> int:
    """Rewrite a raw-sector CD image as a 2048-byte-sector ISO; return sectors.

    Drops each sector's sync/header (and, for 2448-byte sectors, the 96-byte
    subchannel tail), keeping only the 2048 bytes of user data. Mode 1 and
    Mode 2 user data are both 2048 bytes (offset 16 and 24 respectively).
    """
    ss = _raw_cd_sector_size(path)
    if ss is None:
        raise RuntimeError(f"{path} is not a recognizable raw CD image")
    with open(path, "rb") as f:
        first = f.read(16)
    user_off = 16 if first[15] != 0x02 else 24
    n = 0
    with open(path, "rb") as src, open(dest, "wb") as out:
        while True:
            sector = src.read(ss)
            if len(sector) < ss:
                break
            out.write(sector[user_off:user_off + 2048])
            n += 1
    return n


def _cd_data_track_sector(path: Path, max_scan: int = 4096) -> int:
    """Sector index (2048-byte units) where a raw-CD's data track begins.

    Raw dumps often retain the 150-sector lead-in (all-zero sectors) before
    the program area, so the filesystem is not at sector 0. The data track
    starts at the first sector bearing a filesystem signature: an SGI volume
    header (magic at byte 0 of the track) or an ISO9660 PVD ("CD001" lives at
    sector 16 of the track). Returns 0 when no shift is detected.
    """
    with open(path, "rb") as f:
        blob = f.read(max_scan * 2048)
    if not blob:
        return 0
    for sec in range(len(blob) // 2048):
        if blob[sec * 2048:sec * 2048 + 4] == _SGI_VOLHDR_MAGIC:
            return sec
    idx = blob.find(b"CD001")
    if idx >= 0:
        pvd_sector = idx // 2048
        if pvd_sector >= 16:
            return pvd_sector - 16
    return 0


def _trim_cd_lead_in(path: Path) -> int:
    """Trim leading lead-in sectors from a stripped 2048-byte-sector image.

    Rewrites `path` in place so the data track begins at sector 0 (the layout
    `find_efs_partition` / `is_iso9660` expect). Returns the number of sectors
    removed (0 when the track was already at sector 0).
    """
    skip = _cd_data_track_sector(path)
    if skip <= 0:
        return 0
    tmp = path.with_suffix(path.suffix + ".trim")
    with open(path, "rb") as src, open(tmp, "wb") as out:
        src.seek(skip * 2048)
        shutil.copyfileobj(src, out, length=1 << 22)
    tmp.replace(path)
    return skip


def detect_source_kind(path: Path) -> str:
    """Classify a media source: 'dir', 'tar', 'compressed', 'rawcd', 'iso', or 'efs'.

    Content-sniffed, never extension-based. Order matters twice over:

    * ISO first. `tarfile.is_tarfile` only checks for tar magic at offset
      257 of the first block, which real SGI ISOs hit by coincidence (e.g.
      `hot_mix_11.ISO` misdetects as a tar). The ISO9660 test is an exact
      "CD001" at a fixed offset, so it's the more trustworthy signal.
    * Tar before compressed. A `.tar.gz` is a tar (tarfile decompresses it
      transparently) while an `.iso.gz` is a compressed image -- both open
      with the same gzip magic, so only the tar probe separates them.
    * Raw CD before the EFS fallback: a *raw-sector* dump (Alcohol .mdf,
      .bin/.cue, and .nrg files that are actually raw 2352/2448-byte sectors
      rather than a Nero container) isn't an ISO (its filesystem is buried
      inside whole sectors) and isn't a tar, so without this it'd fall through
      to EFS and error. Note: a real Nero `.nrg` *container* (chunked format
      with a "NERO" magic) is NOT a raw dump and is still unsupported.
    """
    if path.is_dir():
        return "dir"
    if is_iso9660(str(path)):
        return "iso"
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except (OSError, tarfile.TarError):
        pass
    if _compression_of(path):
        return "compressed"
    if _raw_cd_sector_size(path):
        return "rawcd"
    return "efs"


def _decompress_to(path: Path, dest: Path, how: str) -> Path:
    """Decompress `path` into directory `dest`; return the resulting file.

    zip archives holding exactly one member unwrap to that member (SGI ISOs
    are often shipped that way, e.g. `IRIX.6.5.Dev_Libraries.cdr.zip`); a
    multi-member zip is left expanded and the caller treats `dest` as a tree.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if how == "zip":
        import zipfile
        with zipfile.ZipFile(path) as zf:
            zf.extractall(dest)
        files = [p for p in dest.rglob("*") if p.is_file()]
        if len(files) == 1:
            return files[0]
        return dest

    if how in ("7z", "rar"):
        # stdlib has no 7z/RAR reader; delegate to the system `7z`.
        import subprocess
        subprocess.run(["7z", "x", "-y", f"-o{dest}", str(path)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        files = [p for p in dest.rglob("*") if p.is_file()]
        if len(files) == 1:
            return files[0]
        return dest

    # strip the compression suffix if present, else just name it "image"
    stem = path.name
    for suf in (".gz", ".xz", ".bz2", ".bzip2", ".Z"):
        if stem.lower().endswith(suf.lower()):
            stem = stem[: -len(suf)]
            break
    else:
        stem = stem + ".image"
    out = dest / stem

    if how == "compress":
        # stdlib has no LZW-.Z reader; delegate to the system `uncompress`.
        import subprocess
        with open(out, "wb") as dst:
            subprocess.run(["uncompress", "-c", str(path)], stdout=dst, check=True)
        return out

    openers = {"gzip": ("gzip", "open"), "xz": ("lzma", "open"), "bzip2": ("bz2", "open")}
    mod_name, fn = openers[how]
    mod = __import__(mod_name)
    with getattr(mod, fn)(path, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst, length=1 << 22)
    return out


def stage_source(path: Path, staging_dir: Path, iso_backend: Optional[str] = None,
                 _depth: int = 0) -> dict:
    """Extract `path` into `staging_dir` and return a small report describing
    where the walkable tree ended up.

    Handles, by content sniffing: a plain directory (used in place, never
    copied), an ISO9660 image, an SGI EFS image, a **tar/`.tardist` bundle**
    (SGI ships patch sets as bare tardists -- one can hold dozens of
    products), and a **whole-file-compressed image** (`.iso.gz`, `.iso.xz`,
    `.cdr.zip`, ...) which is decompressed and then re-dispatched, so
    `foo.iso.gz` transparently becomes an ISO walk.

    The report's `kind` is the FINAL kind actually walked; when unwrapping
    happened, `container` records the chain (e.g. "compressed:gzip") so the
    manifest keeps a record of how the source was opened.
    """
    if _depth > MAX_STAGE_DEPTH:
        raise RuntimeError(f"source unwrapping exceeded depth {MAX_STAGE_DEPTH}: {path}")

    kind = detect_source_kind(path)
    if kind == "dir":
        return {"kind": "dir", "root": path, "extract_stats": None}

    staging_dir.mkdir(parents=True, exist_ok=True)

    if kind == "tar":
        # A tardist is exactly the structure process_root already understands
        # (idb + archives side by side), so unpack it and walk it as a tree.
        with tarfile.open(path, "r:*") as tf:
            # filter="tar" (not "data"): third-party tars of installed
            # trees carry absolute-path symlinks (e.g. /usr/gfx/gfxinfo ->
            # /usr/gfx/gfxinit) which "data" rejects with AbsoluteLinkError.
            # "tar" still blocks ../ path traversal while allowing those
            # (dangling) links -- we only scan for idb/tardist here, never
            # follow them.
            tf.extractall(staging_dir, filter="tar")
            n = len(tf.getmembers())
        return {"kind": "tar", "root": staging_dir, "container": "tar",
                "extract_stats": {"members": n}}

    if kind == "compressed":
        how = _compression_of(path)
        inner_dir = staging_dir / "_decompressed"
        inner = _decompress_to(path, inner_dir, how)
        if inner.is_dir():
            # multi-member zip: walk the expanded tree as-is
            return {"kind": "dir", "root": inner, "container": f"compressed:{how}",
                    "extract_stats": None}
        report = stage_source(inner, staging_dir / "_staged",
                              iso_backend=iso_backend, _depth=_depth + 1)
        inner_container = report.get("container")
        report["container"] = (f"compressed:{how}" if not inner_container
                               else f"compressed:{how}+{inner_container}")
        return report

    if kind == "rawcd":
        # Raw 2352/2448-byte-sector dump (Alcohol .mdf, .nrg, .bin/.cue):
        # rewrite as a 2048-byte ISO (dropping any CD lead-in), then re-dispatch.
        iso = staging_dir / (path.stem + ".iso")
        sectors = _raw_cd_to_iso(path, iso)
        lead_in = _trim_cd_lead_in(iso)
        report = stage_source(iso, staging_dir / "_staged",
                              iso_backend=iso_backend, _depth=_depth + 1)
        tag = f"rawcd:{sectors}s" + (f"-lead{lead_in}" if lead_in else "")
        report["container"] = (tag if not report.get("container")
                               else f"{tag}+{report['container']}")
        return report

    if kind == "iso":
        stats = iso_extract_recursive(str(path), str(staging_dir), backend=iso_backend)
        return {"kind": "iso", "root": staging_dir, "extract_stats": stats.as_dict()}

    ok = extract_efs(path, staging_dir)
    if not ok:
        raise RuntimeError(
            f"could not read {path} as EFS (and it isn't ISO9660, a tar, or a "
            "recognized compressed image either) -- not a recognized install medium"
        )
    return {"kind": "efs", "root": staging_dir, "extract_stats": None}


# ── helpers ──────────────────────────────────────────────────────────────


def _hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rmtree(path: Path) -> None:
    """Remove `path` even when it holds read-only files/directories.

    xorriso (and 7z) extract CD content with its Rock Ridge modes restored --
    0444 files inside 0555 directories -- which a plain `shutil.rmtree`
    cannot unlink (unlink/rmdir needs write permission on the PARENT dir).
    The default `ignore_errors=True` would silently leave gigabytes of
    staging behind, so chmod every entry writable first, then remove.
    """
    path = Path(path)
    try:
        for root, dirs, files in os.walk(path, topdown=False):
            for name in dirs + files:
                p = os.path.join(root, name)
                try:
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                except OSError:
                    pass
            try:
                os.chmod(root, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError:
                pass
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _rel_posix(path: Path, root: Path, prefix: str = "") -> str:
    """Path of `path` relative to `root`, POSIX-separated, with an optional
    `prefix` (used to carry a `.tardist!member` lineage tag)."""
    rel = path.relative_to(root).as_posix()
    return f"{prefix}{rel}" if prefix else rel


def _image_dir_of(image_path: str) -> str:
    """The 'directory' portion of an image-relative path, INCLUDING its
    trailing separator, preserving `!` tardist lineage.

    Image paths of tardist members look like
    `some/dir/foo.tardist!fw_common.idb` -- the `!` lineage tag lives inside
    the LAST slash-separated component, so a plain `rsplit("/", 1)[0]` throws
    it away and every tardist on a disc collapses to the same directory. On
    the Developers Toolbox discs ~318 different tardists each ship their own
    `fw_common.idb`/`fw_common.sw`; without this, all 318 wrote to one
    `data/.../fw_common.extract_manifest.json` and silently overwrote each
    other (metadata/ was unaffected -- it keys off the full path). So treat
    whichever of `/` or `!` appears LAST as the separator.

    Returns "" for a bare filename, "a/b/" for "a/b/c.idb", and
    "a/x.tardist!" for "a/x.tardist!c.idb" -- always safe to concatenate a
    basename onto, and safe as a `Path` component.
    """
    i = max(image_path.rfind("/"), image_path.rfind("!"))
    return image_path[:i + 1] if i >= 0 else ""


def _looks_like_spec(path: Path) -> bool:
    try:
        if path.stat().st_size > SPEC_SNIFF_MAX_SIZE:
            return False
        with open(path, "rb") as f:
            return f.read(len(SPEC_MAGIC)) == SPEC_MAGIC
    except OSError:
        return False


# ── per-product processing ──────────────────────────────────────────────


@contextlib.contextmanager
def _data_root_for(output_dir: Path, idb_dir_rel: str, product: str, retain: bool):
    """Where a product's extracted files get written. When `retain` is
    False, that's a scratch temp dir removed as soon as this product's
    files are hashed -- the corpus keeps metadata/hashes (enough to
    re-verify against the source image later, see `validate_output`) but
    not gigabytes of re-derivable content."""
    if retain:
        yield output_dir / "data" / idb_dir_rel / product
    else:
        with tempfile.TemporaryDirectory(prefix="media_walker_noretain_") as tmp:
            yield Path(tmp)


def _process_idb(idb_path: Path, staged_root: Path, output_dir: Path,
                  hash_algo: str, retain_extractions: bool, prefix: str) -> dict:
    """Parse one `.idb`, write its metadata JSON, extract its archive(s),
    and write the per-file extraction manifest with hashes.

    Returns a summary dict; also returns the set of archive filenames this
    idb accounts for (so the caller doesn't misclassify them as "unclassified"
    or re-sniff them as spec files).
    """
    idb_image_path = _rel_posix(idb_path, staged_root, prefix)
    idb = parse_idb(idb_path)
    product = idb.product

    meta_path = output_dir / "metadata" / idb_image_path
    meta_path = meta_path.with_name(meta_path.name + ".json")
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps({
        "kind": "idb",
        "source_image_path": idb_image_path,
        "source_hash": _hash_file(idb_path, hash_algo),
        "hash_algo": hash_algo,
        "product": idb.product,
        "total_files": sum(1 for e in idb.entries if e.is_file),
        "total_bytes": idb.total_size(),
        "subsystems": sorted(idb.by_subsystem().keys()),
        "entries": [
            {
                "type": e.type, "mode": oct(e.mode), "owner": e.owner,
                "group": e.group, "install_path": e.install_path,
                "archive_path": e.archive_path, "subsystem": e.subsystem,
                "size": e.size, "sum": e.sum, "offset": e.offset,
                "cmpsize": e.cmpsize, "target": e.target, "flags": e.flags,
            }
            for e in idb.entries
        ],
    }, indent=2) + "\n", encoding="utf-8")

    archives_expected = {archive_of_entry(e) for e in idb.entries if e.is_file}

    idb_dir_rel = _image_dir_of(idb_image_path)   # keeps "!tardist" lineage

    file_entries = [e for e in idb.entries if e.is_file]
    manifest_entries = []
    files_hashed = bytes_hashed = 0
    with _data_root_for(output_dir, idb_dir_rel, product, retain_extractions) as data_root:
        stats = extract_product(idb_path.parent, product, data_root, include_man=True)

        source_archives = [
            {
                "archive": name,
                "source_image_path": f"{idb_dir_rel}{name}",
                "hash": _hash_file(idb_path.parent / name, hash_algo),
                "hash_algo": hash_algo,
            }
            for name in stats["archives"]
        ]

        for e in file_entries:
            rel = e.install_path.lstrip("/")
            host_path = data_root / rel
            archive = archive_of_entry(e)
            record = {
                "install_path": e.install_path,
                "archive_path": e.archive_path,
                "subsystem": e.subsystem,
                "mode": oct(e.mode),
                "owner": e.owner,
                "group": e.group,
                "size": e.size,
                "cmpsize": e.cmpsize,
                "offset": e.offset,
                "source_archive_image_path": f"{idb_dir_rel}{archive}",
                "extracted_to": None,
                "hash": None,
                "hash_algo": hash_algo,
            }
            if host_path.is_file():
                # Hash while the file still exists -- if retain_extractions is
                # False, data_root is a temp dir that's gone the moment this
                # `with` block exits. `extracted_to` only gets set when the
                # copy actually persists in the corpus.
                record["hash"] = _hash_file(host_path, hash_algo)
                if retain_extractions:
                    record["extracted_to"] = _rel_posix(host_path, output_dir)
                files_hashed += 1
                bytes_hashed += host_path.stat().st_size
            manifest_entries.append(record)

    extract_manifest_path = output_dir / "data" / idb_dir_rel / f"{product}.extract_manifest.json"
    extract_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    extract_manifest_path.write_text(json.dumps({
        "kind": "extracted_archive_set",
        "product": product,
        "idb_source_image_path": idb_image_path,
        "retain_extractions": retain_extractions,
        "archives_used": stats["archives"],
        "archives_missing": stats["missing_archives"],
        "source_archives": source_archives,
        "files_written": stats["files"],
        "files_hashed": files_hashed,
        "bytes_hashed": bytes_hashed,
        "links": stats["links"],
        "dirs": stats["dirs"],
        "entries": manifest_entries,
    }, indent=2) + "\n", encoding="utf-8")

    return {
        "product": product,
        "idb_source_image_path": idb_image_path,
        "metadata_json": _rel_posix(meta_path, output_dir),
        "extract_manifest_json": _rel_posix(extract_manifest_path, output_dir),
        "archives_used": stats["archives"],
        "archives_missing": stats["missing_archives"],
        "files_written": stats["files"],
        "files_hashed": files_hashed,
    }, archives_expected


def _process_spec(spec_path: Path, staged_root: Path, output_dir: Path,
                   hash_algo: str, prefix: str) -> dict:
    spec_image_path = _rel_posix(spec_path, staged_root, prefix)
    data = spec_path.read_bytes()
    subsystems = parse_spec(data, source=spec_image_path)

    meta_path = output_dir / "metadata" / f"{spec_image_path}.spec.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps({
        "kind": "spec",
        "source_image_path": spec_image_path,
        "source_hash": hashlib.new(hash_algo, data).hexdigest(),
        "hash_algo": hash_algo,
        "subsystem_count": len(subsystems),
        "subsystems": [dataclasses.asdict(s) for s in subsystems],
    }, indent=2) + "\n", encoding="utf-8")

    return {
        "spec_source_image_path": spec_image_path,
        "metadata_json": _rel_posix(meta_path, output_dir),
        "subsystem_count": len(subsystems),
    }


# ── tree walk ────────────────────────────────────────────────────────────


def process_root(staged_root: Path, output_dir: Path, hash_algo: str = DEFAULT_HASH,
                  retain_extractions: bool = True, prefix: str = "",
                  _tmp_holder: Optional[list] = None) -> dict:
    """Walk `staged_root` (a plain directory tree, already extracted or a
    real on-disk directory) and process every product dir / spec / tardist
    found in it. `prefix` tags image-relative paths for nested (tardist)
    sources so lineage back to the outermost image is preserved.
    `retain_extractions=False` keeps only metadata + hashes, not the
    extracted file content (see `_data_root_for`).
    """
    if _tmp_holder is None:
        _tmp_holder = []

    products: list[dict] = []
    specs: list[dict] = []
    tardists: list[dict] = []
    unclassified: list[str] = []

    product_dirs: dict[Path, list[Path]] = {}
    for idb_path in sorted(staged_root.rglob("*.idb")):
        if idb_path.is_file():
            product_dirs.setdefault(idb_path.parent, []).append(idb_path)

    tardist_paths = sorted(staged_root.rglob("*.tardist"))
    tardist_set = set(tardist_paths)

    for d, idb_paths in product_dirs.items():
        archives_expected: set[str] = set()
        idb_names = {p.name for p in idb_paths}
        for idb_path in idb_paths:
            summary, expected = _process_idb(idb_path, staged_root, output_dir,
                                              hash_algo, retain_extractions, prefix)
            products.append(summary)
            archives_expected |= expected

        for child in sorted(d.iterdir()):
            if not child.is_file():
                continue
            if child.name in idb_names or child.name in archives_expected:
                continue
            if child in tardist_set:
                continue  # handled in the tardist pass below
            if _looks_like_spec(child):
                specs.append(_process_spec(child, staged_root, output_dir, hash_algo, prefix))
            else:
                unclassified.append(_rel_posix(child, staged_root, prefix))

    for tardist_path in tardist_paths:
        tar_image_path = _rel_posix(tardist_path, staged_root, prefix)
        extract_tmp = Path(tempfile.mkdtemp(prefix="media_walker_tardist_"))
        _tmp_holder.append(extract_tmp)
        n_members = 0
        try:
            with tarfile.open(tardist_path, "r:*") as tf:
                tf.extractall(extract_tmp, filter="tar")
                n_members = len(tf.getmembers())
        except (tarfile.TarError, OSError) as e:
            tardists.append({
                "tardist_source_image_path": tar_image_path,
                "error": str(e),
            })
            continue

        nested = process_root(extract_tmp, output_dir, hash_algo, retain_extractions,
                               prefix=f"{tar_image_path}!", _tmp_holder=_tmp_holder)
        tardists.append({
            "tardist_source_image_path": tar_image_path,
            "member_count": n_members,
            "products": nested["products"],
            "specs": nested["specs"],
            "nested_tardists": nested["tardists"],
            "unclassified": nested["unclassified"],
        })

    return {
        "products": products,
        "specs": specs,
        "tardists": tardists,
        "unclassified": unclassified,
    }


# ── top-level entry point ───────────────────────────────────────────────


def walk_media(source: Path, output_dir: Path, hash_algo: str = DEFAULT_HASH,
               staging_dir: Optional[Path] = None, keep_staging: bool = False,
               iso_backend: Optional[str] = None, retain_extractions: bool = True) -> dict:
    """Walk an ISO/EFS image (or already-extracted directory) and pull out
    every inst/tardist item. Writes JSON metadata under `output_dir`, plus
    (when `retain_extractions` is True, the default) the extracted, hashed
    data itself. With `retain_extractions=False`, every file is still
    extracted and hashed -- the hash is recorded in the per-product
    `*.extract_manifest.json` -- but the content is discarded immediately
    after hashing rather than kept on disk, since `validate_output` can
    re-derive and re-verify it straight from the source image later using
    that manifest (install_path, subsystem, archive, offset/size, hash).
    This trades "instantly browsable extracted tree" for a corpus that's a
    small fraction of the size. Returns the same summary as `manifest.json`."""
    source = Path(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Hash the image file itself (not the staged/extracted tree) so the
    # manifest can later prove which exact bytes it was generated from --
    # a directory source has no single file to hash.
    source_hash = _hash_file(source, hash_algo) if source.is_file() else None

    owns_staging = staging_dir is None
    staging_dir = Path(staging_dir) if staging_dir else Path(
        tempfile.mkdtemp(prefix="media_walker_stage_"))

    tmp_holder: list = []
    try:
        stage_report = stage_source(source, staging_dir, iso_backend=iso_backend)
        staged_root = stage_report["root"]
        walked = process_root(staged_root, output_dir, hash_algo, retain_extractions,
                              _tmp_holder=tmp_holder)

        manifest = {
            "source": str(source),
            "source_kind": stage_report["kind"],
            "source_container": stage_report.get("container"),
            "source_hash": source_hash,
            "hash_algo": hash_algo,
            "retain_extractions": retain_extractions,
            "extract_stats": stage_report["extract_stats"],
            "product_count": len(walked["products"]),
            "spec_count": len(walked["specs"]),
            "tardist_count": len(walked["tardists"]),
            "unclassified_count": len(walked["unclassified"]),
            **walked,
        }
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest
    finally:
        for d in tmp_holder:
            _rmtree(d)
        if owns_staging and not keep_staging:
            _rmtree(staging_dir)


# ── validation ───────────────────────────────────────────────────────────
#
# validate_output() re-derives the ground-truth inst/tardist inventory from
# the ORIGINAL image (a fresh stage + cheap metadata-only parse, no archive
# extraction) and checks it against a previous walk_media() run's output:
# every idb/spec/tardist the image actually contains has a JSON counterpart,
# every file walk_media claims to have extracted is present on disk with the
# hash it recorded, and any archive recorded "missing" is re-checked against
# the CURRENT resolve_archive() logic (so a bug fix -- like the maintenance-
# overlay fallback above -- shows up here as "go re-run walk_media" instead
# of silently staying stale).


def _archive_name_from_subsystem(subsystem: str) -> str:
    """The archive_of_entry() computation, replayed from a stored subsystem
    string (so validation doesn't need to reconstruct an IDBEntry)."""
    ss = subsystem or ""
    return ss.rsplit(".", 1)[0] if "." in ss else ss


def _dest_key(install_path: str) -> str:
    """The on-disk destination `extract_product` actually writes an entry to,
    used as the reverify index key.

    Must match `output_dir / install_path.lstrip("/")` exactly, INCLUDING
    pathlib's normalization -- real idbs contain paths like
    `/usr/diags/usr/gfx/ucode//lca.rbt` whose doubled slash collapses, so it
    lands on the same file as the sibling entry spelled with one slash (and
    a different size!). Those two collide at extraction: last writer wins and
    BOTH record the winner's hash. Keying the index on the raw string instead
    would treat them as separate files with separate offsets, re-derive the
    loser's bytes, and report a bogus mismatch. (Diagnostics 6.0 and friends
    hit exactly this.)
    """
    return str(Path(install_path.lstrip("/")))


def _build_reverify_index(entries: list, install_dir: Path, product: str) -> dict:
    """For extract_manifest entries that carry a hash but no `extracted_to`
    (retain_extractions=False), work out the CORRECT (archive_path, offset,
    size, cmpsize) to re-read the right bytes straight from the source image.

    The offset recorded per-entry is whatever `.idb` parsing produced --
    for archives shipped with no `off()` tokens at all, that's 0 for every
    entry, and the REAL per-entry offset only exists after
    `archive._reconstruct_offsets` walks the record stream (which
    `extract_product` does internally at extraction time, on its own
    freshly-parsed entries -- that reconstruction never flows back into
    the manifest's per-entry "offset" field). So: group entries needing
    re-verification by their resolved archive, and if a group is entirely
    offset==0, reconstruct it here exactly the same way, once per archive,
    before trusting any of its offsets.

    Multiple DISTINCT idb entries can legitimately share one install_path
    (e.g. an nfs.idb's dskless-client boot images, one per CPU board --
    IP20/IP22/IP26/IP28 -- all installing as "/var/sysgen/system.dl/audio.sm";
    real `inst` picks the one matching the target hardware, something this
    tool doesn't model). When that happens with retain_extractions=True,
    every duplicate physically collides at the same output path and
    `_process_idb` ends up hashing whichever one wrote last -- so ALL of
    those duplicates' recorded hashes already reflect that ONE winner, not
    their own individual content. To match that (already-tested) behavior
    exactly, this keeps offset/size/cmpsize bundled from a SINGLE winning
    entry per install_path (the last one in idb order, same as the on-disk
    write does) rather than looking up offset and size independently --
    mixing one entry's offset with a different duplicate's size/cmpsize
    reads a nonsense byte range and fails every duplicate but one.

    CRITICAL: the per-archive entry list handed to `_reconstruct_offsets`
    must be the SAME list `extract_product` reconstructs over -- i.e. EVERY
    file entry of that archive, in idb order -- not just the subset needing
    re-verification. `_walk_offsets` resynchronizes by looking each stream
    record's self-described path up in a map built from the entries it was
    given; omit even one entry (e.g. a zero-size marker) and the record it
    names becomes unmatchable, the walk bails, and the whole archive silently
    falls back to the order-dependent cumulative estimate -- yielding offsets
    that disagree with extraction for every file after that point.
    (Observed on sgitcl_eoe.help: 1 zero-size entry out of 216 was enough to
    mis-derive 125 files.) So: group everything, reconstruct over everything,
    and only narrow down when building the returned index.

    Returns {install_path: (archive_path, offset, size, cmpsize)} covering
    only entries a re-verify is actually possible for (archive resolvable).
    """
    by_archive: dict = {}
    for e in entries:
        naive = _archive_name_from_subsystem(e.get("subsystem", ""))
        resolved = resolve_archive(install_dir, product, naive)
        if resolved is None:
            continue
        by_archive.setdefault(str(resolved), (resolved, []))[1].append(e)

    index: dict = {}
    for archive_path, group in by_archive.values():
        synth = [
            IDBEntry(type="f", mode=0, owner="", group="", install_path=e["install_path"],
                    subsystem=e.get("subsystem", ""), size=e.get("size", 0),
                    cmpsize=e.get("cmpsize", 0), offset=e.get("offset", 0))
            for e in group
        ]
        if synth and all(se.offset == 0 for se in synth):
            sw_bytes = archive_path.read_bytes()
            _reconstruct_offsets(sw_bytes, synth)
        for e, se in zip(group, synth):
            # only entries that actually need re-verification land in the index;
            # last one wins duplicates, matching extract_product's write loop
            # (which processes entries in this same order)
            if e.get("extracted_to") or not e.get("hash") or not e.get("size"):
                continue
            index[_dest_key(se.install_path)] = (archive_path, se.offset, se.size, se.cmpsize)
    return index


def _discover_idb(idb_path: Path, staged_root: Path, hash_algo: str, prefix: str) -> tuple[dict, set]:
    idb_image_path = _rel_posix(idb_path, staged_root, prefix)
    idb = parse_idb(idb_path)
    product = idb.product
    file_entries = [e for e in idb.entries if e.is_file]
    archives_needed = sorted({archive_of_entry(e) for e in file_entries})
    archives_resolved = {}
    for archive in archives_needed:
        resolved = resolve_archive(idb_path.parent, product, archive)
        archives_resolved[archive] = resolved.name if resolved else None
    return {
        "idb_source_image_path": idb_image_path,
        "source_hash": _hash_file(idb_path, hash_algo),
        "product": product,
        "install_dir": str(idb_path.parent),
        "install_paths": sorted(e.install_path for e in file_entries),
        "archives_needed": archives_needed,
        "archives_resolved": archives_resolved,
    }, set(archives_needed)


def discover_ground_truth(staged_root: Path, hash_algo: str = DEFAULT_HASH, prefix: str = "",
                          _tmp_holder: Optional[list] = None) -> dict:
    """Cheap, read-only counterpart to `process_root`: enumerate every
    idb/spec/tardist an image actually contains (parsing idbs for their
    entry list, but never touching/decompressing archive payloads). Same
    return shape as `process_root` so both can be compared/flattened
    uniformly by `validate_output`."""
    if _tmp_holder is None:
        _tmp_holder = []

    products: list[dict] = []
    specs: list[dict] = []
    tardists: list[dict] = []
    unclassified: list[str] = []

    product_dirs: dict[Path, list[Path]] = {}
    for idb_path in sorted(staged_root.rglob("*.idb")):
        if idb_path.is_file():
            product_dirs.setdefault(idb_path.parent, []).append(idb_path)

    tardist_paths = sorted(staged_root.rglob("*.tardist"))
    tardist_set = set(tardist_paths)

    for d, idb_paths in product_dirs.items():
        archives_expected: set[str] = set()
        idb_names = {p.name for p in idb_paths}
        for idb_path in idb_paths:
            summary, expected = _discover_idb(idb_path, staged_root, hash_algo, prefix)
            products.append(summary)
            archives_expected |= expected

        for child in sorted(d.iterdir()):
            if not child.is_file():
                continue
            if child.name in idb_names or child.name in archives_expected:
                continue
            if child in tardist_set:
                continue
            if _looks_like_spec(child):
                specs.append({
                    "spec_source_image_path": _rel_posix(child, staged_root, prefix),
                    "source_hash": _hash_file(child, hash_algo),
                })
            else:
                unclassified.append(_rel_posix(child, staged_root, prefix))

    for tardist_path in tardist_paths:
        tar_image_path = _rel_posix(tardist_path, staged_root, prefix)
        extract_tmp = Path(tempfile.mkdtemp(prefix="media_walker_validate_tardist_"))
        _tmp_holder.append(extract_tmp)
        try:
            with tarfile.open(tardist_path, "r:*") as tf:
                tf.extractall(extract_tmp, filter="tar")
        except (tarfile.TarError, OSError) as e:
            tardists.append({"tardist_source_image_path": tar_image_path, "error": str(e)})
            continue

        nested = discover_ground_truth(extract_tmp, hash_algo, prefix=f"{tar_image_path}!",
                                       _tmp_holder=_tmp_holder)
        tardists.append({
            "tardist_source_image_path": tar_image_path,
            "products": nested["products"],
            "specs": nested["specs"],
            "nested_tardists": nested["tardists"],
            "unclassified": nested["unclassified"],
        })

    return {"products": products, "specs": specs, "tardists": tardists,
            "unclassified": unclassified}


def _flatten_tree(d: dict) -> tuple[list, list, list, list]:
    """Flatten a process_root()/discover_ground_truth() (or the manifest.json
    dict, which embeds the same shape) into flat (products, specs,
    tardist_records, unclassified) lists, recursing through nested tardists."""
    products = list(d.get("products", []))
    specs = list(d.get("specs", []))
    unclassified = list(d.get("unclassified", []))
    tardist_records: list = []

    def walk(records):
        for t in records:
            tardist_records.append(t)
            if "products" in t:
                products.extend(t["products"])
                specs.extend(t["specs"])
                unclassified.extend(t.get("unclassified", []))
            walk(t.get("nested_tardists", []) or [])

    walk(d.get("tardists", []))
    return products, specs, tardist_records, unclassified


def validate_output(source: Path, output_dir: Path, staging_dir: Optional[Path] = None,
                    keep_staging: bool = False, iso_backend: Optional[str] = None) -> dict:
    """Check a previous `walk_media(source, output_dir)` run for completeness:
    re-derive the inst/tardist inventory straight from `source` and confirm
    every idb/spec/tardist/file it contains has JSON + (for files) a hash-
    verified extracted copy in `output_dir`. Returns a report; does not
    modify `output_dir`."""
    source = Path(source)
    output_dir = Path(output_dir)
    manifest_path = output_dir / "manifest.json"
    problems: list[dict] = []
    counts: dict = {}

    if not manifest_path.is_file():
        return {
            "source": str(source), "output_dir": str(output_dir), "ok": False,
            "problems": [{"type": "manifest_missing", "detail": str(manifest_path)}],
            "counts": counts,
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    hash_algo = manifest.get("hash_algo", DEFAULT_HASH)

    if source.is_file():
        actual_source_hash = _hash_file(source, hash_algo)
        if manifest.get("source_hash") and manifest["source_hash"] != actual_source_hash:
            problems.append({
                "type": "source_image_changed",
                "detail": "the image's hash no longer matches the manifest's recorded "
                          "source_hash -- output_dir was generated from different bytes",
                "recorded": manifest["source_hash"], "actual": actual_source_hash,
            })
        elif not manifest.get("source_hash"):
            problems.append({"type": "source_hash_missing_in_manifest",
                             "detail": "re-run walk_media to backfill source_hash"})

    owns_staging = staging_dir is None
    staging_dir = Path(staging_dir) if staging_dir else Path(
        tempfile.mkdtemp(prefix="media_walker_validate_stage_"))
    tmp_holder: list = []
    try:
        stage_report = stage_source(source, staging_dir, iso_backend=iso_backend)
        truth = discover_ground_truth(stage_report["root"], hash_algo, _tmp_holder=tmp_holder)

        t_products, t_specs, t_tardists, t_unclassified = _flatten_tree(truth)
        m_products, m_specs, m_tardists, m_unclassified = _flatten_tree(manifest)

        t_by_idb = {p["idb_source_image_path"]: p for p in t_products}
        m_by_idb = {p["idb_source_image_path"]: p for p in m_products}
        t_by_spec = {s["spec_source_image_path"] for s in t_specs}
        m_by_spec = {s["spec_source_image_path"] for s in m_specs}
        t_spec_by_path = {s["spec_source_image_path"]: s for s in t_specs}
        t_by_tardist = {t["tardist_source_image_path"] for t in t_tardists}
        m_by_tardist = {t["tardist_source_image_path"] for t in m_tardists}

        for path in sorted(set(t_by_idb) - set(m_by_idb)):
            problems.append({"type": "product_missing_from_manifest", "idb_source_image_path": path})
        for path in sorted(set(m_by_idb) - set(t_by_idb)):
            problems.append({"type": "product_extra_in_manifest", "idb_source_image_path": path})
        for path in sorted(t_by_spec - m_by_spec):
            problems.append({"type": "spec_missing_from_manifest", "spec_source_image_path": path})
        for path in sorted(t_by_tardist - m_by_tardist):
            problems.append({"type": "tardist_missing_from_manifest", "tardist_source_image_path": path})
        for f in sorted(set(t_unclassified) - set(m_unclassified)):
            problems.append({"type": "unclassified_file_not_recorded", "path": f})

        files_checked = files_hash_ok = files_hash_mismatch = files_missing_on_disk = 0
        files_expected_missing_ok = archives_now_resolvable = files_write_gap = 0

        for idb_path, t_prod in t_by_idb.items():
            m_prod = m_by_idb.get(idb_path)
            if m_prod is None:
                continue  # already reported as product_missing_from_manifest

            meta_json_path = output_dir / m_prod["metadata_json"]
            if not meta_json_path.is_file():
                problems.append({"type": "metadata_json_missing", "product": t_prod["product"],
                                 "expected_path": m_prod["metadata_json"]})
            else:
                try:
                    meta = json.loads(meta_json_path.read_text(encoding="utf-8"))
                    if meta.get("total_files") != len(t_prod["install_paths"]):
                        problems.append({
                            "type": "entry_count_mismatch", "product": t_prod["product"],
                            "image_entry_count": len(t_prod["install_paths"]),
                            "metadata_json_entry_count": meta.get("total_files"),
                        })
                    if meta.get("source_hash") != t_prod["source_hash"]:
                        problems.append({
                            "type": "idb_source_hash_mismatch", "product": t_prod["product"],
                            "recorded": meta.get("source_hash"), "actual": t_prod["source_hash"],
                        })
                except (json.JSONDecodeError, OSError) as e:
                    problems.append({"type": "metadata_json_unreadable", "product": t_prod["product"],
                                     "detail": str(e)})

            extract_json_path = output_dir / m_prod["extract_manifest_json"]
            if not extract_json_path.is_file():
                problems.append({"type": "extract_manifest_json_missing", "product": t_prod["product"],
                                 "expected_path": m_prod["extract_manifest_json"]})
                continue
            try:
                extract_manifest = json.loads(extract_json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                problems.append({"type": "extract_manifest_json_unreadable", "product": t_prod["product"],
                                 "detail": str(e)})
                continue

            recorded_paths = {e["install_path"] for e in extract_manifest["entries"]}
            image_paths = set(t_prod["install_paths"])
            if recorded_paths != image_paths:
                problems.append({
                    "type": "entry_set_mismatch", "product": t_prod["product"],
                    "in_image_not_in_manifest": sorted(image_paths - recorded_paths)[:20],
                    "in_manifest_not_in_image": sorted(recorded_paths - image_paths)[:20],
                })

            reverify_index = _build_reverify_index(
                extract_manifest["entries"], Path(t_prod["install_dir"]), t_prod["product"])
            archive_bytes_cache: dict = {}

            for entry in extract_manifest["entries"]:
                files_checked += 1
                if entry.get("extracted_to"):
                    host_path = output_dir / entry["extracted_to"]
                    if not host_path.is_file():
                        files_missing_on_disk += 1
                        problems.append({"type": "file_missing_on_disk", "product": t_prod["product"],
                                         "install_path": entry["install_path"],
                                         "expected_path": entry["extracted_to"]})
                        continue
                    actual_hash = _hash_file(host_path, entry.get("hash_algo", hash_algo))
                    if actual_hash != entry.get("hash"):
                        files_hash_mismatch += 1
                        problems.append({"type": "hash_mismatch", "product": t_prod["product"],
                                         "install_path": entry["install_path"],
                                         "recorded": entry.get("hash"), "actual": actual_hash})
                    else:
                        files_hash_ok += 1
                elif entry.get("hash") and _dest_key(entry["install_path"]) in reverify_index:
                    # Not retained on disk (retain_extractions=False), but a hash
                    # WAS recorded at extraction time -- re-derive the content
                    # straight from the source image's archive (no materialized
                    # copy needed) and check it still matches.
                    # offset/size/cmpsize come bundled from the SAME winning
                    # entry (see _build_reverify_index) -- never mix this
                    # entry's own size/cmpsize with a different duplicate's
                    # offset, or the byte range read is nonsense.
                    archive_path, offset, size, cmpsize = reverify_index[_dest_key(entry["install_path"])]
                    if str(archive_path) not in archive_bytes_cache:
                        archive_bytes_cache[str(archive_path)] = archive_path.read_bytes()
                    sw_bytes = archive_bytes_cache[str(archive_path)]
                    fake = IDBEntry(type="f", mode=0, owner="", group="",
                                    install_path=entry["install_path"],
                                    subsystem=entry.get("subsystem", ""),
                                    size=size, cmpsize=cmpsize, offset=offset)
                    actual_hash = hashlib.new(entry.get("hash_algo", hash_algo),
                                              extract_one(sw_bytes, fake)).hexdigest()
                    if actual_hash != entry.get("hash"):
                        files_hash_mismatch += 1
                        problems.append({"type": "hash_mismatch_against_image",
                                         "product": t_prod["product"],
                                         "install_path": entry["install_path"],
                                         "recorded": entry.get("hash"), "actual": actual_hash,
                                         "detail": "not retained on disk; re-derived from the "
                                                   "source image and the hash no longer matches"})
                    else:
                        files_hash_ok += 1
                elif entry.get("size") == 0:
                    # extract_product intentionally never writes zero-size "f"
                    # entries -- in every real-world case examined they're a
                    # tar-archive directory-self-member carried through as a
                    # bogus file entry, not real content (see archive.py). Not a
                    # problem; don't count it as one.
                    files_expected_missing_ok += 1
                else:
                    naive = _archive_name_from_subsystem(entry.get("subsystem", ""))
                    resolved_name = t_prod["archives_resolved"].get(naive)
                    if resolved_name and resolved_name in extract_manifest.get("archives_used", []):
                        # The owning archive WAS read during that run (it's in
                        # archives_used) -- so this isn't a "missing archive"
                        # gap a re-run would fix. Something about extracting
                        # THIS entry itself failed (e.g. a path collision from
                        # another entry) and needs investigating, not re-running.
                        files_write_gap += 1
                        problems.append({
                            "type": "file_missing_despite_archive_extracted",
                            "product": t_prod["product"], "install_path": entry["install_path"],
                            "archive": resolved_name,
                            "detail": "the owning archive was read during extraction but this file "
                                      "was still never written -- likely a path collision inside "
                                      "extract_product, not stale output; needs investigation",
                        })
                    elif resolved_name:
                        archives_now_resolvable += 1
                        problems.append({
                            "type": "archive_now_resolvable", "product": t_prod["product"],
                            "install_path": entry["install_path"],
                            "detail": "recorded as un-extracted (archive missing at run time), but "
                                      "the current extractor can resolve it now -- re-run walk_media",
                        })
                    else:
                        files_expected_missing_ok += 1

        for path in sorted(t_by_spec & m_by_spec):
            m_spec = next(s for s in m_specs if s["spec_source_image_path"] == path)
            spec_json_path = output_dir / m_spec["metadata_json"]
            if not spec_json_path.is_file():
                problems.append({"type": "spec_metadata_json_missing",
                                 "spec_source_image_path": path,
                                 "expected_path": m_spec["metadata_json"]})
                continue
            try:
                spec_meta = json.loads(spec_json_path.read_text(encoding="utf-8"))
                if spec_meta.get("source_hash") != t_spec_by_path[path]["source_hash"]:
                    problems.append({
                        "type": "spec_source_hash_mismatch", "spec_source_image_path": path,
                        "recorded": spec_meta.get("source_hash"),
                        "actual": t_spec_by_path[path]["source_hash"],
                    })
            except (json.JSONDecodeError, OSError) as e:
                problems.append({"type": "spec_metadata_json_unreadable",
                                 "spec_source_image_path": path, "detail": str(e)})

        counts = {
            "products_in_image": len(t_by_idb), "products_in_manifest": len(m_by_idb),
            "specs_in_image": len(t_by_spec), "specs_in_manifest": len(m_by_spec),
            "tardists_in_image": len(t_by_tardist), "tardists_in_manifest": len(m_by_tardist),
            "files_checked": files_checked, "files_hash_ok": files_hash_ok,
            "files_hash_mismatch": files_hash_mismatch,
            "files_missing_on_disk": files_missing_on_disk,
            "files_expected_missing_ok": files_expected_missing_ok,
            "archives_now_resolvable": archives_now_resolvable,
            "files_write_gap": files_write_gap,
        }
        return {
            "source": str(source), "output_dir": str(output_dir),
            "ok": len(problems) == 0, "problems": problems, "counts": counts,
        }
    finally:
        for d in tmp_holder:
            _rmtree(d)
        if owns_staging and not keep_staging:
            _rmtree(staging_dir)


# ── CLI ────────────────────────────────────────────────────────────────


def _main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Walk an IRIX install medium (ISO/EFS image or directory) "
                    "and extract every inst/tardist item to hashed, JSON-described output.")
    ap.add_argument("source", help="ISO image, EFS/SGI disk image, or already-extracted directory")
    ap.add_argument("-o", "--output", required=True, help="output directory")
    ap.add_argument("--hash", default=DEFAULT_HASH, choices=sorted(hashlib.algorithms_guaranteed),
                    help=f"hash algorithm for extracted files (default: {DEFAULT_HASH})")
    ap.add_argument("--staging-dir", help="use this dir to stage image extraction "
                    "(default: a temp dir, cleaned up afterward)")
    ap.add_argument("--keep-staging", action="store_true",
                    help="don't delete the staging directory afterward")
    ap.add_argument("--iso-backend", choices=("xorriso", "bsdtar", "7z"),
                    help="force a specific ISO extraction backend")
    ap.add_argument("--validate", action="store_true",
                    help="don't extract -- check a previous run in --output against "
                        "--source for completeness (missing JSON/files, hash drift)")
    ap.add_argument("--no-retain-extractions", action="store_true",
                    help="hash every file at extraction time but don't keep the extracted "
                        "content on disk -- just metadata + hashes (a small fraction of the "
                        "size); validate_output can re-verify hashes straight from the "
                        "source image later without needing the extracted copies")
    args = ap.parse_args(argv)

    if args.validate:
        report = validate_output(
            Path(args.source), Path(args.output),
            staging_dir=Path(args.staging_dir) if args.staging_dir else None,
            keep_staging=args.keep_staging, iso_backend=args.iso_backend,
        )
        print(json.dumps(report, indent=2))
        if not report["ok"]:
            print(f"\n{len(report['problems'])} problem(s) found", file=sys.stderr)
        return 0 if report["ok"] else 1

    manifest = walk_media(
        Path(args.source), Path(args.output), hash_algo=args.hash,
        staging_dir=Path(args.staging_dir) if args.staging_dir else None,
        keep_staging=args.keep_staging, iso_backend=args.iso_backend,
        retain_extractions=not args.no_retain_extractions,
    )
    print(f"{manifest['source']}: {manifest['product_count']} products, "
          f"{manifest['spec_count']} specs, {manifest['tardist_count']} tardists, "
          f"{manifest['unclassified_count']} unclassified files -> {args.output}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
