"""The coverage fraction, the model_state census and both controls -- one measurement, one statement.

`check.sh` in the ticket folder and `reproduce.sh` beside it both print a coverage
number, and the parent lane's folder printed THREE that disagreed: its `claim:`
line said 41/41, its `RESULT` line said 36/41, and the bar it enforced was the
parent's 22.  One measurement must have one statement, so every number here is
recomputed from the two committed JSON files and nothing is typed:

    named / touched   registers whose `name` is a real name, over the distinct
                      offsets the traced path touches
    mapped / touched  entries present at all (named or refused) over the same
                      denominator
    census            implemented / fixed / unimp / absent over the map
    labels            the five CMAP/DAC window registers, and whether the map
                      calls them implemented

Both controls are mechanical and both are re-run here:

    POSITIVE   the attributor re-derives named map entries at the SAME
               instruction the map records -- not merely "non-empty"
    NEGATIVE   an offset no function computes, and a real address outside the
               widget, get 0 attributions
    WINDOW     disabling the window form of the model_state reader turns the
               five CMAP/DAC offsets from `implemented` to `absent`
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAP = HERE / "re4_registers.json"
SEQ = HERE / "access_sequence.json"
FIXTURES = HERE / "fixtures"

#: The five registers `mgras_cmap_dac_write()` implements and names through the
#: window form, and which the parent's scan called `absent`.
WINDOW_REGISTERS = (0x70C30, 0x70D18, 0x71810, 0x71890, 0x71910)

#: The positive control: offset -> (function, instruction address) as the map
#: records it.  Re-derived from `fixtures/unix.dis`, a handful of real
#: disassembly lines, because the 33 MB `/unix` disassembly cannot be committed.
POSITIVE = {
    0x72190: ("MgrasVerifyVC3SRAM", "a8000000202b3f30"),
    0x130400: ("MgrasInitDMA", "a8000000202c02e0"),
    0x70400: ("mgras_pcd_write", "a8000000202af334"),
    0x20018: ("MgrasGatherInfo", "a8000000202aec5c"),
    0x130500: ("MgrasCtxsw", "a8000000202bd500"),
}

#: The negative control: an offset no function computes, and a real kernel
#: address outside the widget window.
NEGATIVE = (0x77777, 0x1FFF0000)

#: A role that carries NO name at all.  `ungrounded_field` is deliberately not
#: here: the map names that register (the model's own name for the address) and
#: records that what the field MEANS is ungrounded -- "has a name" and "the
#: name is established" are two different statements, and the fraction counts
#: the first while the entry carries the second.
UNNAMED_ROLES = ("unnamed", "refused")


def load_json(path) -> dict:
    return json.loads(Path(path).read_text())


def load_map() -> dict:
    return json.loads(MAP.read_text())


def load_sequence() -> dict:
    return json.loads(SEQ.read_text())


def registers(doc: dict) -> list:
    return doc["registers"] if isinstance(doc, dict) else doc


def is_named(entry: dict) -> bool:
    """A real name, at the strength the parent's fraction counted as named.

    A `named_by_accessor` entry counts: the kernel function that computes the
    address IS a name ("widget +0x70400 written by mgras_pcd_write"), and the
    parent's 36/41 counted exactly those, so counting them any other way would
    make the two numbers incomparable.  What does NOT count is an entry that
    names nothing: a refusal, an ungrounded field, or a bare unnamed offset.
    """
    if entry.get("role") in UNNAMED_ROLES:
        return False
    name = str(entry.get("name", "")).strip().lower()
    if not name:
        return False
    return not name.startswith(("unnamed", "unknown", "[ungrounded", "refused"))


def coverage(doc: dict, seq: dict) -> dict:
    """The coverage fractions, recomputed -- never read from a typed line."""
    regs = registers(doc)
    touched = {k.lower() for k in seq["counts"]}
    present = {r["offset"].lower() for r in regs}
    named = {r["offset"].lower() for r in regs if is_named(r)}
    return {
        "touched": len(touched),
        "mapped": len(present & touched),
        "named": len(named & touched),
        "named_fraction": "%d/%d" % (len(named & touched), len(touched)),
        "mapped_fraction": "%d/%d" % (len(present & touched), len(touched)),
    }


def census(doc: dict) -> dict:
    cnt = Counter(r.get("model_state") for r in registers(doc))
    return {k: cnt.get(k, 0) for k in ("implemented", "fixed", "unimp", "absent")}


def window_labels(doc: dict) -> dict:
    """How the map labels the five CMAP/DAC window registers."""
    by = {int(r["offset"], 16): r for r in registers(doc)}
    good = [o for o in WINDOW_REGISTERS
            if by.get(o, {}).get("model_state") in ("implemented", "fixed")]
    return {"ok": len(good), "of": len(WINDOW_REGISTERS),
            "fraction": "%d/%d" % (len(good), len(WINDOW_REGISTERS)),
            "bad": [("0x%x" % o) for o in WINDOW_REGISTERS if o not in good]}


def controls(doc: dict | None = None) -> dict:
    """Both attributor controls, re-run against the committed fixture."""
    from . import attr_offsets

    dis = (FIXTURES / "unix.dis").read_text()
    hits = attr_offsets.attribute_text(dis)
    pos = []
    for off, (func, addr) in sorted(POSITIVE.items()):
        got = hits.get(off, [])
        ok = any(h.func == func and "%x" % h.addr == addr for h in got)
        pos.append({"offset": "0x%x" % off, "want_function": func,
                    "want_insn": addr,
                    "got": [h.as_evidence() for h in got], "ok": ok})
    neg = [{"offset": "0x%x" % off, "hits": len(hits.get(off, []))}
           for off in NEGATIVE]
    return {
        "positive": pos,
        "positive_refound": "%d/%d" % (sum(1 for p in pos if p["ok"]), len(pos)),
        "negative": neg,
        "negative_rejected": all(n["hits"] == 0 for n in neg),
        "fixture": "fixtures/unix.dis (%d lines)"
                   % len(dis.splitlines()),
    }


def window_control(tree: str) -> dict:
    """Disabling the window form must turn the five CMAP/DAC offsets `absent`."""
    from . import model_state

    src = Path(tree) / "hw" / "mips" / "sgi_octane.c"
    if not src.is_file():
        return {"ran": False, "reason": "no model tree at %s" % src}
    text = src.read_text(errors="replace")
    on = model_state.census(text, list(WINDOW_REGISTERS), use_window=True)
    off = model_state.census(text, list(WINDOW_REGISTERS), use_window=False)
    on_ok = sum(1 for o in WINDOW_REGISTERS
                if on["state"][o] in ("implemented", "fixed"))
    off_ok = sum(1 for o in WINDOW_REGISTERS
                 if off["state"][o] in ("implemented", "fixed"))
    return {"ran": True, "tree": tree,
            "with_window": "%d/%d" % (on_ok, len(WINDOW_REGISTERS)),
            "without_window": "%d/%d" % (off_ok, len(WINDOW_REGISTERS)),
            "matters": on_ok == len(WINDOW_REGISTERS) and off_ok == 0,
            "states_on": {"0x%x" % o: on["state"][o] for o in WINDOW_REGISTERS},
            "states_off": {"0x%x" % o: off["state"][o] for o in WINDOW_REGISTERS}}


def headline(doc: dict, seq: dict, ctl: dict, tree: str = "") -> dict:
    """Every number the RESULT line prints, in one dict, recomputed."""
    cov = coverage(doc, seq)
    return {
        "named": cov["named_fraction"],
        "mapped": cov["mapped_fraction"],
        "census": census(doc),
        "window": window_labels(doc),
        "controls": ctl,
        "window_control": window_control(tree) if tree else {"ran": False},
        "bytes": {p.name: p.stat().st_size for p in (MAP, SEQ)},
    }


def result_line(doc: dict, seq: dict, ctl: dict, tree: str = "",
                sha: str = "nogit") -> str:
    """The ONE statement of the measurement, for `reproduce.sh` and check.sh."""
    h = headline(doc, seq, ctl, tree)
    c = h["census"]
    w = h["window"]
    verdict = "DURABLE"
    if not (h["controls"]["positive_refound"].split("/")[0] ==
            h["controls"]["positive_refound"].split("/")[1]
            and h["controls"]["negative_rejected"]
            and w["ok"] == w["of"]
            and _ungrounded(doc)):
        verdict = "DURABLE-PARTIAL"
    wc = h["window_control"]
    window_note = ("window form matters %s -> %s" %
                   (wc.get("with_window", "?"), wc.get("without_window", "?"))
                   ) if wc.get("ran") else "window control not run"
    return ("RESULT octane mgras register map: %s -- registers named %s "
            "(parent 22/41, then 36/41); mapped %s; model_state "
            "implemented/fixed/unimp/absent %d/%d/%d/%d; window-form registers "
            "correctly labelled %s; +0x71f00 recorded ungrounded %s; controls "
            "positive %s negative %s; %s; @ %s"
            % (verdict, h["named"], h["mapped"], c["implemented"], c["fixed"],
               c["unimp"], c["absent"], w["fraction"],
               "yes" if _ungrounded(doc) else "no",
               h["controls"]["positive_refound"],
               "yes" if h["controls"]["negative_rejected"] else "no",
               window_note, sha))


def _ungrounded(doc: dict) -> bool:
    e = {r["offset"].lower(): r for r in registers(doc)}.get("0x71f00")
    if not e:
        return False
    blob = json.dumps(e).lower()
    return "ungrounded" in blob and "disagree" not in blob.replace(
        "does not refute", "")


def disagreement_count(doc: dict) -> dict:
    """How many entries still ASSERT a model/kernel disagreement.

    The parent recorded one (`+0x71f00`).  On this map the answer must be 0: the
    field's semantics are ungrounded, which is a different statement, and the
    model's name is not refuted.
    """
    bad = []
    for r in registers(doc):
        note = (r.get("note") or "").lower()
        if "disagrees" in note or "disagreement" in note:
            bad.append(r["offset"])
    return {"asserted": len(bad), "of": len(registers(doc)), "offsets": bad}
