"""ISO9660 extraction via a host backend (bsdtar preferred, xorriso fallback).

No pure-Python ISO9660 reader exists in pyirix; SGI demo CDs that ship as ISO
(rather than EFS) are unpacked here. `bsdtar` reads ISO9660 (incl. Rock Ridge /
Joliet) directly and is the default; `xorriso -osirrox` is the fallback. Both are
commonly present on the dev workstation (see CLAUDE.md build deps).

The public surface mirrors pyirix.efs.reader so callers can treat EFS and ISO
images uniformly:

    from pyirix import iso
    stats = iso.extract_recursive("foo.iso", "/dest/dir")
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field

# ISO9660 Primary Volume Descriptor: "CD001" magic at sector 16 (0x8000), +1.
_PVD_OFFSET = 0x8000
_PVD_MAGIC_OFFSET = _PVD_OFFSET + 1
_PVD_VOLID_OFFSET = _PVD_OFFSET + 40  # 32-byte volume identifier field


@dataclass
class ExtractStats:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    backend: str = ""
    errors: list = field(default_factory=list)

    def as_dict(self):
        return {
            "files": self.files,
            "dirs": self.dirs,
            "bytes": self.bytes,
            "backend": self.backend,
            "errors": self.errors,
        }


def is_iso9660(path: str) -> bool:
    """True if `path` has the ISO9660 'CD001' PVD signature."""
    try:
        with open(path, "rb") as f:
            f.seek(_PVD_MAGIC_OFFSET)
            return f.read(5) == b"CD001"
    except OSError:
        return False


def iso_volume_id(path: str) -> str:
    """Return the ISO9660 volume identifier (trimmed), or '' if unreadable."""
    try:
        with open(path, "rb") as f:
            f.seek(_PVD_VOLID_OFFSET)
            raw = f.read(32)
        return raw.decode("latin-1", "replace").strip().strip("\x00").strip()
    except OSError:
        return ""


# Backend preference order. xorriso is the most reliable on SGI demo ISOs (many
# lack Rock Ridge, which makes bsdtar silently extract zero files), so it leads.
_BACKENDS = ("xorriso", "bsdtar", "7z")


def available_backend() -> str | None:
    """Return the name of the first available extraction backend, or None."""
    for b in _BACKENDS:
        if shutil.which(b):
            return b
    return None


def available_backends() -> list[str]:
    """All available backends, in preference order."""
    return [b for b in _BACKENDS if shutil.which(b)]


def list_recursive(path: str) -> list[str]:
    """List archive member paths inside an ISO (best-effort, via bsdtar -t)."""
    if shutil.which("bsdtar"):
        out = subprocess.run(
            ["bsdtar", "-tf", path],
            capture_output=True, text=True, check=False,
        )
        return [ln for ln in out.stdout.splitlines() if ln]
    raise RuntimeError("list_recursive requires bsdtar")


def extract_recursive(path: str, dest_dir: str, backend: str | None = None) -> ExtractStats:
    """Extract an ISO9660 image to `dest_dir`. Returns ExtractStats.

    Mirrors pyirix.efs.reader.extract_recursive's role. Chooses bsdtar by default
    (handles Rock Ridge long names), falls back to xorriso then 7z.
    """
    if not is_iso9660(path):
        raise ValueError(f"not an ISO9660 image (no CD001 PVD): {path}")
    candidates = [backend] if backend else available_backends()
    if not candidates:
        raise RuntimeError(
            "no ISO extraction backend found (install xorriso, bsdtar, or 7z)"
        )
    os.makedirs(dest_dir, exist_ok=True)

    # Try backends in order; accept the FIRST that yields >0 files. We judge
    # success by extracted file count, NOT exit code: xorriso returns nonzero on
    # a *tolerated* error even when it restored every file, and bsdtar exits 0
    # having extracted nothing on Rock-Ridge-less SGI ISOs.
    last = None
    for be in candidates:
        rc, err = _extract_with(be, path, dest_dir)
        st = _tally(dest_dir, be)
        if st.files > 0:
            st.errors = [err] if (rc != 0 and err) else []
            return st
        last = f"{be}: rc={rc} {err[:200]}"
    raise RuntimeError(f"ISO extraction failed for {path}: {last}")


def _extract_with(backend: str, path: str, dest_dir: str):
    """Run a backend; return (returncode, stderr). Never raises on tool error —
    the caller decides success by counting extracted files."""
    if backend == "bsdtar":
        cmd = ["bsdtar", "-C", dest_dir, "-xf", path]
    elif backend == "xorriso":
        # -osirrox on enables ISO->disk restore; extract whole tree from /.
        # Caller extracts into a fresh dest_dir, so overwrite handling isn't needed.
        cmd = ["xorriso", "-abort_on", "NEVER", "-osirrox", "on",
               "-indev", path, "-extract", "/", dest_dir]
    elif backend == "7z":
        cmd = ["7z", "x", "-y", f"-o{dest_dir}", path]
    else:
        raise ValueError(f"unknown backend: {backend}")
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return res.returncode, res.stderr.strip()


def _tally(dest_dir: str, backend: str) -> ExtractStats:
    st = ExtractStats(backend=backend)
    for root, dirs, files in os.walk(dest_dir):
        st.dirs += len(dirs)
        for name in files:
            st.files += 1
            try:
                st.bytes += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return st
