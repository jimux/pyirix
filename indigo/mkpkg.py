#!/usr/bin/env python3
"""``make-package`` — build the private, arch-independent ``irix-assets``
rpm / deb / tgz from a populated Indigo data root.

After importing IRIX assets once (``pyirix.indigo import``), a user wants a
one-shot package to (re)install the data root instead of re-running the import.
These packages are **pure data** (schemes, fonts, ``.fti`` iconlibs, iconcatalog
symlink trees, FTR DBs, app-defaults, sounds, saver defaults) so they are
**architecture-independent**: ``noarch`` rpm / ``Architecture: all`` deb / a
plain-data tgz — one artifact installs on any distro/arch.

They carry copyrighted SGI content, so their metadata marks them
**NON-REDISTRIBUTABLE** (license / vendor / description) — the same seam the
local-only ``indigo-savers-ep`` package uses.  They install into
``/usr/share/indigo`` so the port's zero-config data-root lookup
(``config.resolve_data_root``: env → config → ``~/.local/share/indigo`` →
``/usr/share/indigo``) finds them with no configuration.

Design choices (see ``progress_notes/indigo_linux/11-irix-assets-package.md``):

* **nfpm route:** we invoke a pinned, sha256-verified ``nfpm`` *directly* with a
  generated YAML, rather than shelling into ``indigo-linux/packaging/lib.sh``
  (bash, and read-only for this work).  The pins mirror ``lib.sh`` exactly and
  the cache dir is shared (``tmp/indigo-packaging/cache``) so the already-fetched
  binary is reused.  The tgz is a plain ``tar`` of the same staged tree (nfpm has
  no tgz packager) — one source of truth, no drift.
* **version:** default derived from the import receipt's date (``updated`` else
  ``created``) as ``YYYY.MM.DD`` (valid for both deb and rpm); ``--version``
  overrides.  The receipt (``import-manifest.json``) is included in the package
  for provenance, and the imported media names go into the description.
* **staging:** the whole data root is copied under ``stage/usr/share/indigo``
  with symlinks preserved as symlinks and modes copied — deb/rpm/tar all keep
  the iconcatalog relative-symlink trees intact (including dangling links that
  point at a full IRIX install).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pyirix.indigo.config import resolve_data_root
from pyirix.indigo.importer import RECEIPT_NAME


# ── pinned nfpm (mirrors indigo-linux/packaging/lib.sh) ───────────────────────
NFPM_VERSION = os.environ.get("NFPM_VERSION", "2.43.0")
NFPM_SHA256 = os.environ.get(
    "NFPM_SHA256",
    "a80d5f724ed70b192ffa8a2bde469c013cef559c8afa3441eb51dd9a918beb6b",
)
NFPM_URL_TMPL = ("https://github.com/goreleaser/nfpm/releases/download/"
                 "v{ver}/nfpm_{ver}_Linux_x86_64.tar.gz")

# Package identity / metadata (NON-REDISTRIBUTABLE — copyrighted SGI content).
PKG_NAME = "irix-assets"
INSTALL_PREFIX = "usr/share/indigo"        # data root lands here on-target
_LICENSE = "Proprietary-SGI-IRIX-NONFREE"
_VENDOR = "Indigo-on-Linux (local only) — contains copyrighted SGI IRIX assets"
_MAINTAINER = "Indigo-on-Linux <indigo@localhost>"
_HOMEPAGE = "https://localhost/indigo-linux"


def _default_scratch() -> Path:
    """Workspace ``tmp/indigo-packaging`` (never system /tmp), matching lib.sh."""
    # this file: .../sgi-irix-re/pyirix/indigo/mkpkg.py → workspace root is 4 up
    here = Path(__file__).resolve()
    ws = here.parents[3]                    # .../qemu-sgi
    return ws / "tmp" / "indigo-packaging"


def _nfpm_cache_dir() -> Path:
    env = os.environ.get("INDIGO_PKG_SCRATCH")
    base = Path(env) if env else _default_scratch()
    return base / "cache"


# ── nfpm bootstrap ────────────────────────────────────────────────────────────

def ensure_nfpm(nfpm: str | None = None) -> str:
    """Return a path to a pinned, sha256-verified ``nfpm`` binary.

    Honors an explicit ``nfpm``/``$NFPM`` first, then the shared cache
    (reusing the binary the packaging skeleton already fetched), then
    downloads + verifies into the cache.
    """
    cand = nfpm or os.environ.get("NFPM")
    if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    cache = _nfpm_cache_dir() / f"nfpm-{NFPM_VERSION}"
    cached = cache / "nfpm"
    if cached.is_file() and os.access(cached, os.X_OK):
        return str(cached)
    cache.mkdir(parents=True, exist_ok=True)
    tgz = cache.parent / f"nfpm-{NFPM_VERSION}.tar.gz"
    if not tgz.is_file():
        import urllib.request
        url = NFPM_URL_TMPL.format(ver=NFPM_VERSION)
        urllib.request.urlretrieve(url, tgz)
    got = hashlib.sha256(tgz.read_bytes()).hexdigest()
    if got != NFPM_SHA256:
        raise RuntimeError(f"nfpm sha256 mismatch: got {got} want {NFPM_SHA256}")
    with tarfile.open(tgz, "r:gz") as tf:
        member = tf.getmember("nfpm")
        tf.extract(member, cache)
    os.chmod(cached, 0o755)
    return str(cached)


# ── version derivation ────────────────────────────────────────────────────────

def _load_receipt(data_root: str) -> dict:
    p = os.path.join(data_root, RECEIPT_NAME)
    if not os.path.isfile(p):
        raise FileNotFoundError(
            f"no {RECEIPT_NAME} in data root {data_root!r}; "
            f"run `pyirix.indigo import` first")
    return json.loads(Path(p).read_text())


def derive_version(receipt: dict) -> str:
    """Default package version from the import receipt, as ``YYYY.MM.DD``.

    Uses the receipt's ``updated`` timestamp (else ``created``, else today).
    Date-based so re-imports of the same media on the same day are stable and
    a later re-import sorts newer; ``--version`` overrides for anything finer.
    """
    stamp = receipt.get("updated") or receipt.get("created")
    dt: datetime
    if stamp:
        try:
            dt = datetime.fromisoformat(stamp)
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return f"{dt.year:04d}.{dt.month:02d}.{dt.day:02d}"


def _media_names(receipt: dict) -> list[str]:
    names = []
    for s in receipt.get("sources", []):
        n = s.get("name")
        if n and n not in names:
            names.append(n)
    return names


# ── staging ───────────────────────────────────────────────────────────────────

@dataclass
class StageStats:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    stage_root: str = ""
    install_root: str = ""            # stage/usr/share/indigo


def stage_data_root(data_root: str, stage: str) -> StageStats:
    """Copy the whole data root under ``stage/usr/share/indigo``.

    Symlinks are preserved as symlinks (iconcatalog trees, font aliases —
    including dangling links to a full IRIX install); file modes are copied.
    """
    data_root = os.path.abspath(data_root)
    if not os.path.isdir(data_root):
        raise FileNotFoundError(f"data root not a directory: {data_root}")
    stage = os.path.abspath(stage)
    if os.path.exists(stage):
        shutil.rmtree(stage)
    dest = os.path.join(stage, INSTALL_PREFIX)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    # symlinks=True → copy links verbatim (dangling ok); copy2 preserves modes.
    shutil.copytree(data_root, dest, symlinks=True)

    st = StageStats(stage_root=stage, install_root=dest)
    for dp, dirs, files in os.walk(dest):
        st.dirs += 1
        for fn in files:
            full = os.path.join(dp, fn)
            if os.path.islink(full):
                st.symlinks += 1
            else:
                st.files += 1
        for dn in dirs:
            full = os.path.join(dp, dn)
            if os.path.islink(full):
                st.symlinks += 1
                st.dirs -= 1            # symlinked dir counted as a symlink
    return st


# ── nfpm YAML ─────────────────────────────────────────────────────────────────

def _description(media: list[str]) -> str:
    prov = ("imported from: " + ", ".join(media)) if media else \
        "imported from user-supplied IRIX media."
    return (
        "IRIX Indigo Magic desktop assets for Indigo-on-Linux (PRIVATE).\n"
        "NON-REDISTRIBUTABLE: contains copyrighted SGI IRIX content "
        "(schemes, fonts, filetype/FTR databases, iconcatalog, app-defaults, "
        "sounds, saver defaults). Do NOT publish this artifact; it is for the "
        "importing user's own private repository only.\n"
        "Architecture-independent (pure data). Installs the port's data root "
        "under /usr/share/indigo.\n"
        + prov
    )


def render_nfpm_yaml(version: str, media: list[str], *,
                     name: str = PKG_NAME) -> str:
    """Build the nfpm YAML (one config → deb + rpm).  ``src`` is relative to
    the build cwd (nfpm does not expand ${VAR} in a ``type: tree`` src)."""
    desc = _description(media)
    # Indent the (multi-line) description as a YAML block scalar.
    desc_block = "\n".join("  " + ln for ln in desc.splitlines())
    return f"""# GENERATED by pyirix.indigo make-package -- do not edit.
# PRIVATE, NON-REDISTRIBUTABLE: copyrighted SGI IRIX assets.
name: {name}
arch: all
platform: linux
version: "{version}"
section: x11
priority: optional
maintainer: {_MAINTAINER}
vendor: {_VENDOR}
homepage: {_HOMEPAGE}
license: {_LICENSE}
description: |
{desc_block}

contents:
  - src: stage/{INSTALL_PREFIX}
    dst: /{INSTALL_PREFIX}
    type: tree
"""


# ── build ─────────────────────────────────────────────────────────────────────

@dataclass
class MakeResult:
    data_root: str = ""
    version: str = ""
    outdir: str = ""
    artifacts: dict = field(default_factory=dict)      # fmt -> path
    stage: StageStats = field(default_factory=StageStats)
    media: list = field(default_factory=list)
    receipt_included: bool = False


def _build_tgz(stage_root: str, out_path: str, version: str) -> str:
    """Plain tar.gz of the staged tree (untar into ``/``); root-owned, symlinks
    preserved (tar never follows them)."""
    src = os.path.join(stage_root, "usr")
    if os.path.exists(out_path):
        os.unlink(out_path)

    def _reset(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        return ti

    with tarfile.open(out_path, "w:gz") as tf:
        tf.add(src, arcname="usr", filter=_reset)
    return out_path


def make_package(data_root: str | None = None, *,
                 dest: str | None = None,
                 outdir: str | None = None,
                 version: str | None = None,
                 formats=("deb", "rpm", "tgz"),
                 name: str = PKG_NAME,
                 nfpm: str | None = None,
                 work_dir: str | None = None) -> MakeResult:
    """Build the ``irix-assets`` package(s) from a populated data root.

    ``data_root``/``dest`` resolve exactly like the importer (explicit >
    ``$INDIGO_DATA_ROOT`` > config > default).  Returns a :class:`MakeResult`.
    """
    root = resolve_data_root(data_root or dest)
    receipt = _load_receipt(root)
    ver = version or derive_version(receipt)
    media = _media_names(receipt)

    if outdir is None:
        outdir = os.path.abspath("./dist-irix-assets")
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)

    if work_dir is None:
        work_dir = os.path.join(_default_scratch(), "mkpkg-build", name)
    work_dir = os.path.abspath(work_dir)
    os.makedirs(work_dir, exist_ok=True)

    stage = os.path.join(work_dir, "stage")
    stats = stage_data_root(root, stage)

    res = MakeResult(data_root=root, version=ver, outdir=outdir,
                     stage=stats, media=media)
    res.receipt_included = os.path.isfile(
        os.path.join(stats.install_root, RECEIPT_NAME))

    nfpm_formats = [f for f in formats if f in ("deb", "rpm")]
    if nfpm_formats:
        yaml_text = render_nfpm_yaml(ver, media, name=name)
        yaml_path = os.path.join(work_dir, "nfpm.yaml")
        Path(yaml_path).write_text(yaml_text)
        nfpm_bin = ensure_nfpm(nfpm)
        for fmt in nfpm_formats:
            # cwd = work_dir so the relative `src: stage/...` resolves.
            subprocess.run([nfpm_bin, "package", "-f", yaml_path,
                            "-p", fmt, "-t", outdir],
                           cwd=work_dir, check=True,
                           capture_output=True, text=True)
        # nfpm names: <name>_<ver>_all.deb ; <name>-<ver>-1.noarch.rpm
        if "deb" in nfpm_formats:
            res.artifacts["deb"] = os.path.join(
                outdir, f"{name}_{ver}_all.deb")
        if "rpm" in nfpm_formats:
            res.artifacts["rpm"] = os.path.join(
                outdir, f"{name}-{ver}-1.noarch.rpm")

    if "tgz" in formats:
        tgz = os.path.join(outdir, f"{name}-{ver}.tgz")
        _build_tgz(stage, tgz, ver)
        res.artifacts["tgz"] = tgz

    # Sanity: every promised artifact exists.
    for fmt, path in res.artifacts.items():
        if not os.path.isfile(path):
            raise RuntimeError(f"{fmt} artifact not produced: {path}")
    return res
