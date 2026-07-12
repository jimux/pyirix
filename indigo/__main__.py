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


def _cmd_appsync(args) -> int:
    from pyirix.indigo.appsync import run_appsync
    dirs = args.appdir or None
    res = run_appsync(dest=args.dest, dirs=dirs, force=args.force)
    print(f"data root:   {res.data_root}")
    print(f"apps:        {len(res.apps)}  (changed={res.changed})")
    print(f"hostapps.ftr: {res.ftr_path}")
    print(f"launchers:   {res.launch_dir}")
    print("  genres: " + ", ".join(f"{k}={v}" for k, v in
                                    sorted(res.genre_counts.items())))
    print("  pages:")
    for page, names in sorted(res.pages.items()):
        print(f"      {page:<14} {len(names):>4}")
    if args.watch:
        print("  --watch: NOT IMPLEMENTED (TODO: inotify refresh arrives "
              "with the fm port; run appsync at session start for now)")
    return 0


def _cmd_fti_check(args) -> int:
    from pyirix.indigo import fti
    paths = fti.find_corpus_fti(args.root)
    ascii_p = [p for p in paths if fti.is_ascii_fti(p)]
    other = len(paths) - len(ascii_p)
    fails = 0
    unknown = {}
    for p in ascii_p:
        try:
            with open(p, errors="replace") as f:
                ic = fti.parse(f.read(), strict=args.strict, path=p)
        except Exception as e:
            fails += 1
            print(f"  FAIL {p}: {e}")
            continue
        for w in ic.warnings:
            if "unknown command" in w:
                cmd = w.split("'")[1]
                unknown[cmd] = unknown.get(cmd, 0) + 1
    print(f"filetype iconlib .fti: {len(paths)}  "
          f"(ascii-vector {len(ascii_p)}, binary/empty {other})")
    print(f"parse failures: {fails}/{len(ascii_p)}")
    if unknown:
        print(f"unknown commands: {unknown}")
    return 1 if fails else 0


def _cmd_fti_render(args) -> int:
    from pyirix.indigo import fti
    im, icon = fti.render_file(args.file, args.size)
    im.save(args.out)
    print(f"{args.file}: {len(icon.ops)} ops -> {args.out} ({args.size}px)")
    if icon.warnings:
        print(f"  warnings: {icon.warnings[:5]}")
    return 0


def _cmd_fti_sheet(args) -> int:
    from pyirix.indigo import fti
    paths = [p for p in fti.find_corpus_fti(args.root) if fti.is_ascii_fti(p)]
    if args.limit:
        paths = paths[:args.limit]
    out = fti.contact_sheet(paths, args.out, cell=args.size, cols=args.cols)
    print(f"contact sheet: {len(paths)} icons -> {out}")
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

    ap_sync = sub.add_parser(
        "appsync",
        help="generate Icon Catalog entries from host .desktop applications")
    ap_sync.add_argument("--dest", default=None, help="data root (override)")
    ap_sync.add_argument("--appdir", action="append", default=None,
                         help="override .desktop scan dir(s) (repeatable)")
    ap_sync.add_argument("--force", action="store_true",
                         help="force regenerate even if content is unchanged")
    ap_sync.add_argument("--watch", action="store_true",
                         help="(stub) live-refresh; arrives with the fm port")
    ap_sync.set_defaults(func=_cmd_appsync)

    fc = sub.add_parser("fti-check",
                        help="parse-coverage check over corpus .fti trees")
    fc.add_argument("root", nargs="+", help="root dir(s) to walk for "
                    "filetype/**/iconlib/*.fti")
    fc.add_argument("--strict", action="store_true",
                    help="fail on any grammar deviation")
    fc.set_defaults(func=_cmd_fti_check)

    fr = sub.add_parser("fti-render", help="rasterize one .fti to PNG")
    fr.add_argument("file", help="path to a .fti file")
    fr.add_argument("-o", "--out", default="icon.png", help="output PNG")
    fr.add_argument("--size", type=int, default=64, help="pixel size")
    fr.set_defaults(func=_cmd_fti_render)

    fs = sub.add_parser("fti-sheet", help="render a contact sheet PNG")
    fs.add_argument("root", nargs="+", help="root dir(s) to walk")
    fs.add_argument("-o", "--out", default="contact_sheet.png")
    fs.add_argument("--size", type=int, default=64, help="cell pixel size")
    fs.add_argument("--cols", type=int, default=12)
    fs.add_argument("--limit", type=int, default=0, help="cap icon count")
    fs.set_defaults(func=_cmd_fti_sheet)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
