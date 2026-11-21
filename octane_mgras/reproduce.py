#!/usr/bin/env python3
"""Re-derive the RE4/VC3 register map's headline from the committed artifact.

Two arms, so a ticket folder needs neither a VM nor a 195 MB trace:

    --check   (default) re-read the two committed JSON files, recompute every
              number the RESULT line prints, and re-run both attributor controls
              and the model_state window control against the committed fixtures
    --full    additionally re-disassemble `/unix` from the named golden and
              re-derive the map from the trace, which is what a model change
              should run before trusting the `model_state` column

Exit 0 when it measured (a measured failure is still a measurement), 2 when it
could not.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import coverage

HERE = Path(__file__).resolve().parent


def _sha(repo: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "--short",
                               "HEAD"], capture_output=True, text=True,
                              check=False).stdout.strip() or "nogit"
    except OSError:
        return "nogit"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="the committed artifact")
    ap.add_argument("--full", action="store_true",
                    help="re-disassemble /unix and re-derive from the trace")
    ap.add_argument("--repo", default=str(HERE.parents[2]),
                    help="the sgi-irix-re checkout the sha is reported from")
    ap.add_argument("--tree", default="",
                    help="the model tree for the window-form control")
    args = ap.parse_args(argv)

    doc = coverage.load_map()
    seq = coverage.load_sequence()
    ctl = coverage.controls(doc)
    tree = args.tree
    if not tree:
        for cand in (Path.home() / "qemu-sgi" / "qemu-sgi-repo",
                     HERE.parents[3] / "qemu-sgi-repo"):
            if (cand / "hw" / "mips" / "sgi_octane.c").is_file():
                tree = str(cand)
                break
    print("map %s (%d registers), sequence %s (%d offsets)"
          % (HERE / "re4_registers.json", len(coverage.registers(doc)),
             HERE / "access_sequence.json", len(seq["counts"])), file=sys.stderr)
    print("positives re-found %s; negative rejected %s"
          % (ctl["positive_refound"], ctl["negative_rejected"]), file=sys.stderr)
    wc = coverage.window_control(tree) if tree else {"ran": False}
    if wc.get("ran"):
        print("window control: with %s without %s"
              % (wc["with_window"], wc["without_window"]), file=sys.stderr)
    if args.full:
        rc = _full(tree)
        if rc != 0:
            return rc
    print(coverage.result_line(doc, seq, ctl, tree, _sha(Path(args.repo))))
    return 0





if __name__ == "__main__":
    sys.exit(main())
