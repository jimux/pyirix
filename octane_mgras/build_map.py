#!/usr/bin/env python3
"""Build the committed RE4/VC3 register map from the two committed measurements.

Inputs (all re-derived, none typed):

  access_sequence.json   the distinct offsets the traced path touches, with their
                         write counts, sizes and first-touch order  (the
                         denominator of the coverage fraction)
  tmp/unix.dis           the disassembly of the named /unix; `attr_offsets.py`
                         names the kernel accessor that computes each offset
  <model tree>           `hw/mips/sgi_octane.c`; `model_state.py` classifies each
                         offset implemented/fixed/unimp/absent by ALL FOUR handler
                         forms.

The output is one entry per register:

  offset, width, dir, name, model_state, evidence, writer_functions, block, role,
  note

`name` is deliberately honest about its strength, and the marker in it is what a
reader (and `check.sh`) keys on:

  MGRAS_X                  the model names this exact address, and the kernel's
                           accessor agrees on what it is for
  MGRAS_BASE+MGRAS_X_OFF    the model names it through a window base; the model
                           implements it in the window form
  widget +0xNNN written by F
                           [UNNAMED FIELD]: the kernel witness pins the function,
                           not the field's meaning
  REFUSED                  the witness computes the address from a pointer that
                           is not the widget base; see `note`
  [UNGROUNDED FIELD]       two measurements point at each other and neither
                           settles the field's meaning
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "tools"))

import attr_offsets as attr            # noqa: E402
import model_state as mstate           # noqa: E402

#: Blocks are named from the model's own bases, so a reader can group the map
#: without a second table.
BLOCKS = [("MGRAS_HQ", 0x11000, 0x11100, "HQ (host queue) flags/intr"),
          ("MGRAS_USER", 0x20000, 0x20100, "HQ user flag / gather"),
          ("MGRAS_RE4", 0x40000, 0x40100, "RE4 flush/HQ3 window"),
          ("MGRAS_MCO", 0x61000, 0x61100, "MCO / DCB control"),
          ("MGRAS_XMAP", 0x71c00, 0x72000, "XMAP mode generator"),
          ("MGRAS_CMAP", 0x70c00, 0x71000, "CMAP palette"),
          ("MGRAS_DAC", 0x71800, 0x71c00, "ADV7162 RAMDAC"),
          ("MGRAS_VC3", 0x72000, 0x74000, "VC3 / MCO registers"),
          ("MGRAS_HQ_CMD", 0x120000, 0x121000, "HQ command FIFO"),
          ("MGRAS_TXTBL", 0x130000, 0x131000, "HAG TxTbl window")]


def block_of(off: int) -> str:
    for name, lo, hi, _desc in BLOCKS:
        if lo <= off < hi:
            return name
    return ""


def model_names(consts: dict) -> dict:
    """{offset: [model constant name, ...]} for every constant that IS an offset.

    A constant ending `_BASE` names a window, not a register, so it is skipped;
    `BASE + X_OFF` pairs are folded to the address they name.
    """
    out: dict = {}
    for name, val in consts.items():
        if name.endswith("_BASE"):
            continue
        out.setdefault(val, []).append(name)
    for base_name, base in consts.items():
        if not base_name.endswith("_BASE"):
            continue
        for name, val in consts.items():
            if not name.endswith("_OFF"):
                continue
            out.setdefault(base + val, []).append("%s+%s" % (base_name, name))
    return out


def index_before_data(events, port: int, data: int) -> dict:
    """How many writes to *data* are immediately preceded by a write to *port*.

    Necessary but NOT sufficient for a per-DID (indexed) register: PP1_SELECT
    (+0x71c08) passes the same test and is one plain register, which is why this
    measurement is recorded BESIDE the field name and cannot settle it.
    """
    n = preceded = 0
    idx = []
    prev = None
    for _t, off, _s, val in events:
        if off == data:
            n += 1
            if prev is not None and prev[0] == port:
                preceded += 1
                idx.append(prev[1])
        prev = (off, val)
    return {"writes": n, "preceded_by_index": preceded,
            "index_values": sorted(set(idx)), "port": "0x%x" % port}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sequence", default=str(HERE / "tmp/access-sequence.json"))
    ap.add_argument("--dis", default=str(HERE / "tmp/unix.dis"))
    ap.add_argument("--tree", default=str(HERE.parent.parent / "qemu-sgi-repo"))
    ap.add_argument("--trace", default=str(HERE / "vm/trace-hk.trace"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--unix-sha256", required=True)
    ap.add_argument("--golden", required=True)
    ap.add_argument("--tree-sha", default="")
    ap.add_argument("--no-window", action="store_true",
                    help="build with the window form DISABLED (the control arm)")
    args = ap.parse_args(argv)

    seq = json.loads(Path(args.sequence).read_text())
    offsets = sorted(int(k, 16) for k in seq["counts"])
    src = Path(args.tree) / "hw" / "mips" / "sgi_octane.c"
    text = src.read_text(errors="replace")
    consts = mstate.read_defines(text)
    states = mstate.census(text, offsets, use_window=not args.no_window)
    names = model_names(consts)

    dis = Path(args.dis).read_text(errors="replace")
    hits = attr.attribute_text(dis, offsets)

    events = []
    tr = Path(args.trace)
    if tr.is_file():
        import access_seq
        with open(tr, errors="replace") as f:
            events = access_seq.parse(f)

    registers = []
    for off in offsets:
        key = "0x%x" % off
        writers = hits.get(off, [])
        funcs = []
        for h in writers:
            if h.func not in funcs:
                funcs.append(h.func)
        sizes = seq["sizes"].get(key, [])
        dirs = sorted({h.dir for h in writers}) or (["w"] if sizes else [])
        width = sizes[0] if sizes else (writers[0].width if writers else 0)
        state = states["state"][off]
        cand = sorted(set(names.get(off, [])))
        entry = {
            "offset": key,
            "width": width,
            "dir": "rw" if len(dirs) > 1 else (dirs[0] if dirs else "w"),
            "traced_writes": seq["counts"][key],
            "traced_sizes": sizes,
            "model_state": state,
            "model_constants": cand,
            "block": block_of(off),
            "writer_functions": funcs,
            "evidence": [],
        }
        for h in writers[:6]:
            ev = h.as_evidence()
            ev["object"] = "/unix (sha256 below)"
            entry["evidence"].append(ev)
        if cand:
            entry["evidence"].append(
                {"source": "model", "constants": cand,
                 "handler": (states["evidence"][off] or [""])[0]})

        if off in REFUSED:
            entry["name"] = "REFUSED widget +0x%x" % off
            entry["role"] = "refused"
            entry["note"] = REFUSED[off]
        elif off in UNGROUNDED:
            entry["name"] = "[UNGROUNDED FIELD] widget +0x%x" % off
            entry["role"] = UNGROUNDED[off]["role"]
            entry["note"] = UNGROUNDED[off]["note"]
            if events:
                entry["index_before_data"] = [
                    index_before_data(events, p, off)
                    for p in UNGROUNDED[off]["probe_ports"]]
                pp1 = index_before_data(events, 0x71C88, 0x71C08)
                entry["index_before_data"].append(
                    dict(pp1, note="+0x71c08 PP1_SELECT passes the same test "
                                   "and the model treats it as ONE register, so "
                                   "index-before-data does not prove per-DID"))
        elif cand:
            entry["name"] = cand[0]
            entry["role"] = "model_named"
            entry["note"] = ("the model names this address (%s)"
                             % ", ".join(cand)) if state in ("implemented",
                                                             "fixed") else (
                "the model names this address but implements no handler for it, "
                "so a write lands in the generic reg[] play-back")
        elif funcs:
            entry["name"] = ("widget +0x%x written by %s [UNNAMED FIELD]"
                             % (off, funcs[0]))
            entry["role"] = "named_by_accessor"
            entry["note"] = ("the kernel accessor %s computes widget +0x%x; that "
                             "pins the function, not the field's meaning"
                             % (funcs[0], off))
        else:
            entry["name"] = "widget +0x%x [UNNAMED FIELD]" % off
            entry["role"] = "unnamed"
            entry["note"] = ("no held accessor computes this address; the traced "
                             "path touches it and nothing pins it")
        registers.append(entry)

    doc = {
        "schema": "pyirix/octane_mgras/re4_registers.json v2",
        "golden": args.golden,
        "unix_sha256": args.unix_sha256,
        "trace": seq.get("source", {}).get("trace", ""),
        "trace_sha256": seq.get("trace_sha256", ""),
        "model_tree": str(src),
        "model_tree_sha": args.tree_sha,
        "model_state_reader": "tools/model_state.py (all four handler forms%s)"
                              % ("" if not args.no_window
                                 else ", window form DISABLED"),
        "attributor": "tools/attr_offsets.py",
        "registers": registers,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")

    touched = len(offsets)
    named = [r for r in registers
             if not r["name"].lower().lstrip("[").startswith(("unnamed",
                                                             "widget", "refused",
                                                             "unknown"))]
    cnt = Counter(r["model_state"] for r in registers)
    print("%d registers over %d traced offsets; named %d/%d; "
          "implemented/fixed/unimp/absent %d/%d/%d/%d"
          % (touched, touched, len(named), touched, cnt.get("implemented", 0),
             cnt.get("fixed", 0), cnt.get("unimp", 0), cnt.get("absent", 0)))
    return 0


#: The two offsets the parent refused, with the instruction that defeats the
#: dataflow.  The refusal is correct and stays: `MgrasFlushHQ3`'s `a1` is
#: `ld a1,56(sp)` -- a caller's struct pointer, not the widget base.
REFUSED = {
    0x40080: ("MgrasFlushHQ3 stores widget +0x40080 only as `sw v1,128(a1)` and "
              "`a1` is reloaded from the caller's stack slot (`ld a1,56(sp)` at "
              "a8000000202b53d4 / a8000000202b5408): a caller-supplied pointer, "
              "not the widget base. Attributing it would claim a register from a "
              "pointer the callee never computed, so it is refused on evidence."),
    0x40088: ("same writer and same refused base as +0x40080: `sw at,136(a1)` at "
              "a8000000202b5560 with `a1` = `ld a1,56(sp)`."),
}

#: +0x71f00: the model's MGRAS_XMAP_DIB_OFF name is NOT refuted, and the field's
#: semantics are NOT established.  The parent recorded this as a disagreement on
#: the strength of "every writer is a timing/palette function"; the parent's own
#: trace shows 100% of its writes preceded by an INDEX write with DID-varying
#: values, which is the per-DID CRS shape the model documents.
UNGROUNDED = {
    0x71f00: {
        "role": "ungrounded_field",
        "probe_ports": [0x71C88],
        "note": ("the model names widget +0x71f00 MGRAS_XMAP_DIB_OFF (the XMAP "
                 "digital input bypass, CRS(6)|DW4 = 0x300 on MGRAS_XMAP_BASE) "
                 "and implements no handler for it; every /unix accessor that "
                 "computes the address is a timing/palette function "
                 "(MgrasSetTiming, MgrasSetXMAPTiming, MgrasSetColors, "
                 "MgrasInitXMAP, MgrasCalcScreenSize, MgrasSyncPPRDRAMs). The "
                 "kernel witness therefore does NOT refute the model's name: "
                 "on the traced path 100% of writes to this address follow a "
                 "write to the XMAP INDEX port +0x71c88 with per-DID index "
                 "values, which is exactly the indexed CRS shape the model "
                 "documents. Index-before-data is necessary and NOT sufficient "
                 "(+0x71c08 PP1_SELECT passes the same test and cannot be "
                 "per-DID), and mgrashw.h -- which the model cites by line for "
                 "every CRS number -- is not held by the project. So: field "
                 "SEMANTICS UNGROUNDED, the model's name NOT refuted."),
    },
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
