#!/usr/bin/env python3
"""CLI for the Indigo asset importer.

    python3 -m pyirix.indigo import <source>... [--dest DIR]
    python3 -m pyirix.indigo verify [--dest DIR]
    python3 -m pyirix.indigo make-package [--dest DIR] [--outdir DIR]
                                          [--version V] [--only FMT[,FMT]]

`import` accepts any mix of the supported source formats (dist tree, EFS/ISO
CD image, .tardist, IRIX disk image, plain root tree); later sources add to /
overwrite earlier ones in the same data root. `verify` checks presence, min
counts and format sanity of an already-populated data root. `make-package`
builds the private, arch-independent `irix-assets` rpm/deb/tgz from a
populated data root so a reinstall is one package install (NON-REDISTRIBUTABLE:
copyrighted SGI content; for the user's own private repo).

Data root resolution: ``--dest`` > ``$INDIGO_DATA_ROOT`` >
``~/.config/indigo/config`` (``data_root``) > ``~/.local/share/indigo``.
"""

from __future__ import annotations

import argparse
import os
import sys

from pyirix.indigo.config import resolve_data_root
from pyirix.indigo.importer import run_import
from pyirix.indigo.verify import verify as run_verify


def _cmd_import(args) -> int:
    dest, receipt, stats = run_import(args.source, dest=args.dest,
                                      run_poststeps=not args.no_poststeps)
    print(f"imported into: {dest}")
    for st in stats:
        ident = st.source_identity.get("name", "?")
        print(f"  [{st.source_type}] {ident} ({st.mode}): "
              f"{st.files} files, {st.symlinks} symlinks, "
              f"{st.dirs} dirs, {st.errors} errors")
        if st.per_category:
            cats = ", ".join(f"{k}={v}" for k, v in sorted(st.per_category.items()))
            print(f"      {cats}")
    cats = receipt.get("categories", {})
    print("  final category counts:")
    for name, info in cats.items():
        print(f"      {name:<12} {info['count']:>6}  ({info['count_kind']})")
    for post in receipt.get("post_steps", []):
        print(f"  post-step {post.get('step')}: {post.get('status')}"
              + (f" ({len(post.get('dirs', []))} dirs)"
                 if post.get('dirs') else ""))
    return 0


def _cmd_verify(args) -> int:
    rep = run_verify(args.dest)
    print(rep.summary())
    return 0 if rep.ok else 1


def _cmd_make_package(args) -> int:
    from pyirix.indigo.mkpkg import make_package
    formats = (tuple(f.strip() for f in args.only.split(",") if f.strip())
               if args.only else ("deb", "rpm", "tgz"))
    res = make_package(dest=args.dest, outdir=args.outdir,
                       version=args.version, formats=formats)
    print(f"data root:  {res.data_root}")
    print(f"version:    {res.version}")
    if res.media:
        print(f"media:      {', '.join(res.media)}")
    print(f"staged:     {res.stage.files} files, {res.stage.symlinks} symlinks, "
          f"{res.stage.dirs} dirs  (receipt included: {res.receipt_included})")
    print(f"outdir:     {res.outdir}")
    for fmt in ("deb", "rpm", "tgz"):
        p = res.artifacts.get(fmt)
        if p:
            sz = os.path.getsize(p)
            print(f"  {fmt:<3} {os.path.basename(p)}  ({sz} bytes)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pyirix.indigo",
                                 description="Indigo Magic asset importer "
                                             "(bring-your-own IRIX media).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    imp = sub.add_parser("import", help="import assets from IRIX media")
    imp.add_argument("source", nargs="+",
                     help="source(s): dist tree / CD image / .tardist / "
                          "disk image / root tree")
    imp.add_argument("--dest", default=None, help="data root (override)")
    imp.add_argument("--no-poststeps", action="store_true",
                     help="skip mkfontdir/mkfontscale font post-step")
    imp.set_defaults(func=_cmd_import)

    ver = sub.add_parser("verify", help="verify a populated data root")
    ver.add_argument("--dest", default=None, help="data root (override)")
    ver.set_defaults(func=_cmd_verify)

    mk = sub.add_parser("make-package",
                        help="build the private irix-assets rpm/deb/tgz "
                             "from a populated data root")
    mk.add_argument("--dest", default=None, help="data root (override)")
    mk.add_argument("--outdir", default=None,
                    help="artifact output dir (default ./dist-irix-assets)")
    mk.add_argument("--version", default=None,
                    help="package version (default: from receipt date)")
    mk.add_argument("--only", default=None,
                    help="comma-separated subset of deb,rpm,tgz "
                         "(default: all three)")
    mk.set_defaults(func=_cmd_make_package)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
