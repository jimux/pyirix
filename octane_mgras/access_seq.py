#!/usr/bin/env python3
"""Turn the model's `mgras-win` write trace into the access sequence the map counts.

The denominator of the map's coverage fraction is "the distinct offsets the
traced path touches", so the window has to be defined mechanically and stated:

  * the window runs from the FIRST to the LAST `HQ_HAG_IM_DMA_CTRL` token write
    (`0x80b04` to `+0x120400`) -- the texture-upload trigger;
  * outside it the kernel spins millions of writes on unrelated registers (after
    the demo is killed, `+0x40068` alone is written millions of times), which is
    why an unbounded trace makes every count meaningless;
  * `counts`/`sizes`/`first_touch_order` are over the window only, and an offset
    written with more than one size records every size.

The trace is the model's own instrument (`MGRAS_WIN_DBG`, see
`hw/mips/sgi_octane.c`), line-capped; it is hundreds of MB and is never
committed.  This file's output is small and is.

Usage: access_seq.py <trace> <out.json> [--unix-sha256 <sha>] [--golden <name>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

#: The HQ token whose write starts the HAG transfer: `(0x80b << 8) | 4`.
TRIGGER_OFF = 0x120400
TRIGGER_VAL = (0x80B << 8) | 4

WIN_RX = re.compile(r"mgras-win t=(\d+) W off=0x([0-9a-f]+) size=(\d+) "
                    r"val=0x([0-9a-f]+)")


def parse(lines) -> list:
    """[(t, off, size, val)] for every logged write, in trace order."""
    out = []
    for line in lines:
        m = WIN_RX.search(line)
        if m:
            out.append((int(m.group(1)), int(m.group(2), 16),
                        int(m.group(3)), int(m.group(4), 16)))
    return out


def build(events: list) -> dict:
    """The window, its offsets, and their counts -- all recomputed, never typed."""
    trig = [i for i, (_t, off, _s, val) in enumerate(events)
            if off == TRIGGER_OFF and val == TRIGGER_VAL]
    if not trig:
        return {"window": None, "triggers": 0, "counts": {}, "sizes": {},
                "first_touch_order": [], "writes": 0,
                "note": "no HQ_HAG_IM_DMA_CTRL token write: the demo never "
                        "reached the texture upload, so there is no window"}
    lo, hi = trig[0], trig[-1]
    win = events[lo:hi + 1]
    counts: dict = {}
    sizes: dict = {}
    order: list = []
    for _t, off, size, _v in win:
        key = "0x%x" % off
        counts[key] = counts.get(key, 0) + 1
        sizes.setdefault(key, set()).add(size)
        if key not in order:
            order.append(key)
    return {"window": {"first_trigger_index": lo, "last_trigger_index": hi,
                       "first_t": win[0][0] if win else None,
                       "last_t": win[-1][0] if win else None,
                       "trace_events_total": len(events)},
            "triggers": len(trig),
            "writes": len(win),
            "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
            "sizes": {k: sorted(v) for k, v in sorted(sizes.items())},
            "first_touch_order": order,
            "trigger_off": "0x%x" % TRIGGER_OFF,
            "trigger_val": "0x%x" % TRIGGER_VAL}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("trace")
    ap.add_argument("out")
    ap.add_argument("--unix-sha256", default="")
    ap.add_argument("--golden", default="")
    ap.add_argument("--trace-name", default="")
    args = ap.parse_args(argv)
    trace = Path(args.trace)
    if not trace.is_file():
        print("NOT MEASURED: no trace at %s" % trace)
        return 2
    with open(trace, "r", errors="replace") as f:
        events = parse(f)
    seq = build(events)
    seq["source"] = {
        "instrument": "MGRAS_WIN_DBG (model writes in the 16 MB MGRAS widget)",
        "trace": args.trace_name or trace.name,
        "trace_bytes": trace.stat().st_size,
        "golden": args.golden,
        "unix_sha256": args.unix_sha256,
    }
    seq["trace_sha256"] = _sha256(trace)
    Path(args.out).write_text(json.dumps(seq, indent=1) + "\n")
    if seq["window"] is None:
        print("NOT MEASURED: %s" % seq["note"])
        return 2
    print("%d writes, %d distinct offsets, %d triggers -> %s"
          % (seq["writes"], len(seq["counts"]), seq["triggers"], args.out))
    return 0


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
