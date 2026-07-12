#!/usr/bin/env python3
"""Data-root resolution for the Indigo asset importer.

Resolution order (first hit wins):
  1. explicit ``--dest DIR`` (handled by the caller, not here)
  2. ``$INDIGO_DATA_ROOT``
  3. ``data_root`` key in ``~/.config/indigo/config``
  4. an existing per-user root ``~/.local/share/indigo`` (a fresh import)
  5. an existing system root ``/usr/share/indigo`` (an installed
     ``irix-assets`` package — found with zero configuration)
  6. otherwise the default per-user root ``~/.local/share/indigo``
     (the location a fresh import will create)

Steps 4–6 make the port and the importer agree with the packaged install
layout: the ``irix-assets`` package (``pyirix.indigo make-package``) installs
under ``/usr/share/indigo``, and a user import stays at ``~/.local/share/indigo``
and takes precedence when both are present. Import into an empty machine still
lands at the per-user default (step 6).

The config file is a trivial ``key = value`` / ``key: value`` text file
(blank lines and ``#`` comments ignored) so it stays dependency-free and
hand-editable.
"""

from __future__ import annotations

import os
from pathlib import Path


DEFAULT_DATA_ROOT = "~/.local/share/indigo"
SYSTEM_DATA_ROOT = "/usr/share/indigo"
CONFIG_PATH = "~/.config/indigo/config"


def _read_config(path: str | None = None) -> dict[str, str]:
    # read the module global at call time so it stays monkeypatchable
    p = Path(os.path.expanduser(path if path is not None else CONFIG_PATH))
    out: dict[str, str] = {}
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("=", ":"):
            if sep in line:
                k, v = line.split(sep, 1)
                out[k.strip()] = v.strip()
                break
    return out


def resolve_data_root(dest: str | None = None) -> str:
    """Resolve the data root to an absolute path (not created here)."""
    if dest:
        return os.path.abspath(os.path.expanduser(dest))
    env = os.environ.get("INDIGO_DATA_ROOT")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    cfg = _read_config().get("data_root")
    if cfg:
        return os.path.abspath(os.path.expanduser(cfg))
    # Zero-config discovery: prefer an existing populated root — the per-user
    # import over an installed system package — else fall back to the per-user
    # default (which a fresh import will create).
    user_default = os.path.abspath(os.path.expanduser(DEFAULT_DATA_ROOT))
    if os.path.isdir(user_default):
        return user_default
    system = os.path.abspath(os.path.expanduser(SYSTEM_DATA_ROOT))
    if os.path.isdir(system):
        return system
    return user_default
