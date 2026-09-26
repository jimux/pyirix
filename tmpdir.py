"""Workspace-default scratch directory for pyirix.

On the project nodes ``/tmp`` is a small RAM tmpfs; filling it kills every
session's Bash tool, and a full ``/tmp`` also makes large temporaries fail
silently. Anything large — raw disk conversions, tardist extractions, EFS
staging, package builds — must therefore land on the workspace, not ``/tmp``.

Resolution order for the scratch root:

1. ``PYIRIX_TMPDIR`` if set (created if absent);
2. the workspace ``tmp/pyirix/`` directory, found by walking up from this file
   to the ``.qemu-sgi-workspace`` marker (so a sub-repo checkout resolves the
   same root as ``sgi_workspace.workspace_root()``);
3. ``<system tmp>/pyirix`` as a last resort for a standalone install.

This module intentionally avoids importing ``sgi_workspace`` so ``pyirix``
remains installable on its own.
"""

import os
import tempfile
from pathlib import Path

WORKSPACE_MARKER = ".qemu-sgi-workspace"
TMPDIR_ENV = "PYIRIX_TMPDIR"


def tmp_root() -> Path:
    """Return (and create) the scratch root directory."""
    env = os.environ.get(TMPDIR_ENV)
    if env:
        root = Path(env)
    else:
        start = Path(__file__).resolve()
        root = Path(tempfile.gettempdir()) / "pyirix"
        for d in [start.parent, *start.parents]:
            if (d / WORKSPACE_MARKER).exists():
                root = d / "tmp" / "pyirix"
                break
    root.mkdir(parents=True, exist_ok=True)
    return root


def tmp_dir(prefix: str = "pyirix_") -> str:
    """Create and return a unique scratch directory under :func:`tmp_root`."""
    return tempfile.mkdtemp(prefix=prefix, dir=str(tmp_root()))


def fsync_path(path) -> None:
    """fsync a file and then its containing directory (best effort)."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    try:
        d = os.path.dirname(os.path.abspath(str(path))) or "."
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
