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

★ A UNIX SOCKET IS NOT A TEMPORARY.  ``PF_UNIX`` addresses live in
``sockaddr_un.sun_path``, 108 bytes on Linux, and a path must be STRICTLY
shorter.  The workspace scratch root is deep by design (a lane's effort folder
under a ticket under a workspace), so ``socket_dir()`` may fall back to a short
root for SOCKET PATHS ONLY -- a few dozen bytes in ``/tmp``-class storage --
naming the choice on stderr.  Nothing large ever lands there: every other
temporary still comes from :func:`tmp_dir`.
"""

import os
import sys
import tempfile
from pathlib import Path

WORKSPACE_MARKER = ".qemu-sgi-workspace"
TMPDIR_ENV = "PYIRIX_TMPDIR"
SOCKETDIR_ENV = "PYIRIX_SOCKDIR"
# sizeof(sockaddr_un.sun_path) on Linux; a unix socket path must be SHORTER.
SUN_PATH_MAX = 108


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


def socket_path_fits(path: str) -> bool:
    """Whether ``path`` is a legal unix socket address (strictly shorter than sun_path)."""
    return len(path) < SUN_PATH_MAX


def _socket_child_len(prefix: str, leaf: str) -> int:
    """The length of ``<prefix>XXXXXXXX/<leaf>``: what ``tempfile.mkdtemp`` puts under the
    root (an 8-character random suffix) plus the socket file name."""
    return len(prefix) + 8 + len(os.sep) + len(leaf)


def socket_dir(prefix: str = "nbd_", leaf: str = "sock") -> str:
    """A directory a unix socket named ``<prefix>XXXXXXXX/<leaf>`` can be bound under.

    ``PYIRIX_SOCKDIR`` names one outright.  Otherwise :func:`tmp_root` is used when that
    socket path fits, and a short root (``<system tmp>/pyirix-sock/``, ~27 characters) when
    it does not -- the layout charter rule 9 mandates puts a lane's scratch ~95 characters
    deep, which with ``nbd_XXXXXXXX/sock`` is past the kernel's 108-byte ``sun_path`` limit.

    Only the SOCKET is placed in the short root: a unix socket address is a few dozen bytes
    of kernel bookkeeping, not a temporary, and every temporary still comes from
    :func:`tmp_dir`.  The choice is announced on stderr (once per root) so a reader of a
    failing run can see which directory qemu-nbd was told to bind.
    """
    env = os.environ.get(SOCKETDIR_ENV)
    if env:
        Path(env).mkdir(parents=True, exist_ok=True)
        return env
    root = str(tmp_root())
    if socket_path_fits(os.path.join(root, "x" * _socket_child_len(prefix, leaf))):
        return root
    short = Path(tempfile.gettempdir()) / "pyirix-sock"
    short.mkdir(parents=True, exist_ok=True)
    key = (root, str(short))
    if key not in _ANNOUNCED:
        _ANNOUNCED.add(key)
        print(f"pyirix: scratch root {root!r} cannot hold a {prefix}XXXXXXXX/{leaf} socket "
              f"path under the {SUN_PATH_MAX}-byte unix-socket limit; binding sockets in "
              f"{str(short)!r} instead (a socket, not a temporary; {SOCKETDIR_ENV} names "
              f"one outright)", file=sys.stderr)
    return str(short)


_ANNOUNCED: set[tuple[str, str]] = set()


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
