#!/usr/bin/env python3
"""CLI for the Indigo asset importer.

    python3 -m pyirix.indigo import <source>... [--dest DIR]
    python3 -m pyirix.indigo verify [--dest DIR]

`import` accepts any mix of the supported source formats (dist tree, EFS/ISO
CD image, .tardist, IRIX disk image, plain root tree); later sources add to /
overwrite earlier ones in the same data root. `verify` checks presence, min
counts and format sanity of an already-populated data root.

Data root resolution: ``--dest`` > ``$INDIGO_DATA_ROOT`` >
``~/.config/indigo/config`` (``data_root``) > ``~/.local/share/indigo``.
"""

from __future__ import annotations

import argparse
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

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
