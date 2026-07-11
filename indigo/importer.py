#!/usr/bin/env python3
"""The asset-import engine.

Given an opened `Source` (its `FileProvider`), populate an IRIX-shaped data
root with the assets named in ``manifest.MANIFEST``, then write/merge an
``import-manifest.json`` receipt at the root.

Two layouts are handled uniformly:

* **installed-tree** — the provider already exposes installed paths
  (``usr/lib/X11/schemes/…``). Used for plain root trees and IRIX disk
  images. We walk each manifest prefix and copy files, **preserving
  symlinks as symlinks** (iconcatalog pages, font aliases).

* **dist-media** — the provider exposes inst products (``<product>.idb`` +
  ``.sw`` archives), possibly nested one level down (a CD/EFS volume that
  contains several dist trees). We parse each idb, and for every entry whose
  install path a manifest prefix owns, extract the bytes from the owning
  ``.sw`` archive (via ``pyirix.dist.archive``) or recreate the symlink from
  the idb ``symval`` target.

Multiple sources can be imported into one data root (later sources add to /
overwrite earlier ones); the receipt accumulates every source's identity and
per-category counts, and the final category counts are recomputed from the
data root on disk.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pyirix.indigo import manifest as M
from pyirix.indigo.config import resolve_data_root
from pyirix.indigo.providers import FileProvider, HostFileProvider, _norm
from pyirix.indigo.sources import Source, open_source, file_sha256

from pyirix.dist.idb import parse_idb_bytes
from pyirix.dist.archive import (
    extract_one, archive_of_entry, _reconstruct_offsets,
)

import hashlib


RECEIPT_NAME = "import-manifest.json"
SCHEMA_VERSION = 2


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ImportStats:
    source_type: str = ""
    source_identity: dict = field(default_factory=dict)
    mode: str = ""                       # 'installed_tree' | 'dist_media'
    files: int = 0
    symlinks: int = 0
    dirs: int = 0
    errors: int = 0
    per_category: dict = field(default_factory=dict)   # name -> count written
    products: list = field(default_factory=list)


# ── layout detection ─────────────────────────────────────────────────────

def _find_products(provider: FileProvider) -> list[tuple[str, str]]:
    """Locate inst products: (product_dir_rel, product_name) for each
    ``<product>.idb`` at the provider root or one level below."""
    found: list[tuple[str, str]] = []

    def scan(rel: str):
        for name, kind in provider.listdir(rel):
            if kind == "f" and name.endswith(".idb"):
                product = name[:-4]
                # require a sibling archive (.sw*) to avoid stray idbs
                sibs = [n for n, k in provider.listdir(rel)
                        if k == "f" and (n == f"{product}.sw"
                                         or n.startswith(f"{product}.sw"))]
                if sibs:
                    found.append((rel, product))

    scan("")
    if not found:
        # descend one level (CD/EFS volume of dist trees)
        for name, kind in provider.listdir(""):
            if kind == "d":
                scan(name)
    return found


def detect_mode(provider: FileProvider) -> tuple[str, list]:
    """Return ('dist_media', products) or ('installed_tree', [])."""
    products = _find_products(provider)
    if products:
        return "dist_media", products
    if provider.exists("usr") and provider.is_dir("usr"):
        return "installed_tree", []
    # last resort: if any manifest prefix exists, treat as installed tree
    for e in M.MANIFEST:
        if provider.exists(e.prefix):
            return "installed_tree", []
    return "installed_tree", []


# ── writing ──────────────────────────────────────────────────────────────

def _write_file(dest_root: str, rel: str, data: bytes,
                file_map: dict, source_id: str):
    rel = _norm(rel)
    dst = os.path.join(dest_root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    # If an existing symlink occupies the path, remove it first.
    if os.path.islink(dst):
        os.unlink(dst)
    with open(dst, "wb") as f:
        f.write(data)
    file_map[rel] = {
        "kind": "file",
        "size": len(data),
        "sha256": _sha256_bytes(data),
        "source": source_id,
    }


def _write_symlink(dest_root: str, rel: str, target: str,
                   file_map: dict, source_id: str):
    rel = _norm(rel)
    dst = os.path.join(dest_root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.lexists(dst):
        if os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst)
        else:
            os.unlink(dst)
    os.symlink(target, dst)
    file_map[rel] = {
        "kind": "symlink",
        "target": target,
        "source": source_id,
    }


# ── installed-tree extraction ────────────────────────────────────────────

def _import_installed(provider: FileProvider, dest_root: str,
                      file_map: dict, source_id: str) -> ImportStats:
    st = ImportStats(mode="installed_tree")
    for entry in M.MANIFEST:
        if not provider.exists(entry.prefix):
            continue
        cat_count = 0
        for rel, kind in provider.walk(entry.prefix):
            try:
                if kind == "d":
                    os.makedirs(os.path.join(dest_root, _norm(rel)),
                                exist_ok=True)
                    st.dirs += 1
                elif kind == "l":
                    target = provider.readlink(rel)
                    _write_symlink(dest_root, rel, target, file_map, source_id)
                    st.symlinks += 1
                    cat_count += 1
                else:  # file
                    data = provider.read(rel)
                    _write_file(dest_root, rel, data, file_map, source_id)
                    st.files += 1
                    cat_count += 1
            except Exception:
                st.errors += 1
        st.per_category[entry.name] = cat_count
    return st


# ── dist-media extraction ────────────────────────────────────────────────

def _import_dist(provider: FileProvider, products: list, dest_root: str,
                 file_map: dict, source_id: str) -> ImportStats:
    st = ImportStats(mode="dist_media")
    st.products = [p for _, p in products]
    for prod_dir, product in products:
        idb_rel = f"{prod_dir}/{product}.idb" if prod_dir else f"{product}.idb"
        try:
            idb = parse_idb_bytes(provider.read(idb_rel), product=product)
        except Exception:
            st.errors += 1
            continue

        # Collect only entries our manifest owns, grouped by owning archive.
        wanted_by_archive: dict[str, list] = {}
        for e in idb.entries:
            me = M.match_entry(e.install_path)
            if me is None:
                continue
            if e.is_dir:
                os.makedirs(os.path.join(dest_root,
                                         e.install_path.lstrip("/")),
                            exist_ok=True)
                st.dirs += 1
            elif e.is_symlink:
                try:
                    _write_symlink(dest_root, e.install_path,
                                   e.target or "", file_map, source_id)
                    st.symlinks += 1
                    st.per_category[me.name] = st.per_category.get(me.name, 0) + 1
                except Exception:
                    st.errors += 1
            elif e.is_file:
                wanted_by_archive.setdefault(archive_of_entry(e), []).append((me, e))

        for archive, items in wanted_by_archive.items():
            arch_rel = f"{prod_dir}/{archive}" if prod_dir else archive
            if not provider.exists(arch_rel):
                st.errors += len(items)
                continue
            try:
                sw_bytes = provider.read(arch_rel)
            except Exception:
                st.errors += len(items)
                continue
            entries = [e for _, e in items]
            if entries and all(e.offset == 0 for e in entries):
                _reconstruct_offsets(sw_bytes, entries)
            for me, e in items:
                try:
                    data = extract_one(sw_bytes, e)
                    _write_file(dest_root, e.install_path, data,
                                file_map, source_id)
                    st.files += 1
                    st.per_category[me.name] = st.per_category.get(me.name, 0) + 1
                except Exception:
                    st.errors += 1
    return st


# ── post steps (fonts) ───────────────────────────────────────────────────

_FONT_EXT = (".pcf", ".pcf.z", ".snf", ".snf.z", ".bdf", ".fon",
             ".ttf", ".pfa", ".pfb", ".fb", ".scb")


def _run_font_poststep(dest_root: str) -> dict:
    fonts_root = os.path.join(dest_root, "usr/lib/X11/fonts")
    result = {"step": "mkfontdir", "status": "n/a", "dirs": []}
    if not os.path.isdir(fonts_root):
        return result
    have_dir = shutil.which("mkfontdir")
    have_scale = shutil.which("mkfontscale")
    if not have_dir and not have_scale:
        # find font dirs to record as pending
        pend = _font_dirs(fonts_root, dest_root)
        result["status"] = "pending"
        result["reason"] = "mkfontdir/mkfontscale not on host"
        result["dirs"] = pend
        return result
    done = []
    for d in _font_dirs(fonts_root, absolute=True):
        try:
            if have_scale:
                subprocess.run(["mkfontscale", d], check=False,
                               capture_output=True, timeout=120)
            if have_dir:
                subprocess.run(["mkfontdir", d], check=False,
                               capture_output=True, timeout=120)
            done.append(os.path.relpath(d, dest_root))
        except Exception:
            pass
    result["status"] = "done" if done else "empty"
    result["dirs"] = done
    return result


def _font_dirs(fonts_root: str, dest_root: str | None = None,
               absolute: bool = False) -> list[str]:
    out = []
    for dirpath, _dirs, files in os.walk(fonts_root):
        if any(f.lower().endswith(_FONT_EXT) for f in files):
            out.append(dirpath if absolute
                       else os.path.relpath(dirpath, dest_root or fonts_root))
    return sorted(out)


# ── receipt ──────────────────────────────────────────────────────────────

def _recompute_categories(dest_root: str) -> dict:
    cats = {}
    for e in M.MANIFEST:
        base = os.path.join(dest_root, e.prefix)
        rels = []
        if os.path.isdir(base):
            for dp, _d, files in os.walk(base):
                for fn in files:
                    full = os.path.join(dp, fn)
                    rels.append(os.path.relpath(full, dest_root))
                # include symlinks (os.walk lists them under files if they
                # point to files, under dirs if to dirs; capture link dirs too)
            # also count symlink dirs
            for dp, dirs, _files in os.walk(base):
                for dn in list(dirs):
                    full = os.path.join(dp, dn)
                    if os.path.islink(full):
                        rels.append(os.path.relpath(full, dest_root))
        cats[e.name] = {
            "count": e.counts(rels),
            "count_kind": e.count_kind,
            "min_count": e.min_count,
            "required": e.required,
            "prefix": e.prefix,
            "post_step": e.post_step,
        }
    return cats


def _load_receipt(dest_root: str) -> dict:
    p = os.path.join(dest_root, RECEIPT_NAME)
    if os.path.isfile(p):
        try:
            return json.loads(Path(p).read_text())
        except Exception:
            pass
    return {
        "schema": SCHEMA_VERSION,
        "data_root": os.path.abspath(dest_root),
        "created": _now_iso(),
        "sources": [],
        "files": {},
        "post_steps": [],
    }


def _write_receipt(dest_root: str, receipt: dict):
    receipt["updated"] = _now_iso()
    receipt["categories"] = _recompute_categories(dest_root)
    p = os.path.join(dest_root, RECEIPT_NAME)
    Path(p).write_text(json.dumps(receipt, indent=2, sort_keys=False))


# ── public API ───────────────────────────────────────────────────────────

def import_source(src: Source, dest_root: str, receipt: dict) -> ImportStats:
    """Import one opened Source into dest_root, updating the receipt dict."""
    provider = src.provider
    mode, products = detect_mode(provider)
    source_id = f"{src.stype}:{src.identity.get('name', '')}"
    if mode == "dist_media":
        st = _import_dist(provider, products, dest_root,
                          receipt["files"], source_id)
    else:
        st = _import_installed(provider, dest_root,
                               receipt["files"], source_id)
    st.source_type = src.stype
    st.source_identity = dict(src.identity)
    receipt["sources"].append({
        **src.identity,
        "mode": st.mode,
        "files": st.files,
        "symlinks": st.symlinks,
        "dirs": st.dirs,
        "errors": st.errors,
        "per_category": st.per_category,
        "products": st.products,
        "imported_at": _now_iso(),
    })
    return st


def run_import(source_paths, dest=None, run_poststeps=True):
    """Import one or more sources into the resolved data root.

    Returns (data_root, receipt, [ImportStats,...]).
    """
    dest_root = resolve_data_root(dest)
    os.makedirs(dest_root, exist_ok=True)
    receipt = _load_receipt(dest_root)
    all_stats = []
    for sp in source_paths:
        with open_source(sp) as src:
            st = import_source(src, dest_root, receipt)
            all_stats.append(st)

    if run_poststeps:
        post = _run_font_poststep(dest_root)
        # keep only the latest font post-step result
        receipt["post_steps"] = [
            p for p in receipt.get("post_steps", [])
            if p.get("step") != "mkfontdir"
        ]
        receipt["post_steps"].append(post)

    _write_receipt(dest_root, receipt)
    return dest_root, receipt, all_stats
