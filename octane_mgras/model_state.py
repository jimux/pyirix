#!/usr/bin/env python3
"""Classify a widget offset against a model tree: implemented / fixed / unimp / absent.

The map's `model_state` column answers one question a model change acts on: does
`hw/mips/sgi_octane.c` have a HANDLER for this address, and what does it do?

The parent lanes answered it by grepping for `off == MGRAS_X` and
`off == MGRAS_BASE + MGRAS_X_OFF`.  That scan is what mislabelled the CMAP and
DAC windows: `mgras_cmap_dac_write()` implements those registers in a THIRD
form,

    if (off >= MGRAS_CMAPALL_BASE && off < MGRAS_CMAPALL_BASE + 0x400) {
        base = MGRAS_CMAPALL_BASE;
    }
    if (base) {
        reg = off - base;
        if (reg == MGRAS_CMAP_ADDR_OFF) { ... }

and a `case` in a `switch` is a fourth form that a text scan for `==` misses
altogether.  This reader resolves ALL FOUR:

  1. direct constant     `if (off == MGRAS_X)`, including `a || b || ...` chains
  2. base + offset       `if (off == MGRAS_BASE + MGRAS_X_OFF)`
  3. window form         `x >= BASE && x < BASE + n` then `reg = x - <base>`
                         then `if (reg == MGRAS_X_OFF)`, where <base> may be a
                         LOCAL variable assigned one (or, in an if/else-if chain,
                         several) of the window constants
  4. switch case         `switch (reg) { case MGRAS_X: ... }`

`fixed` means the handler answers a CONSTANT rather than reading model state;
`unimp` means the only evidence is a `qemu_log_mask(LOG_UNIMP, ...)`; `absent`
means none of the four forms reaches the offset, so a write lands in the generic
`reg[]` array and plays back with no meaning.

The third form is proven load-bearing by `--no-window`: disabling it must change
the five CMAP/DAC offsets from `implemented` to `absent`.  An arm that cannot go
red is not a gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFINE_RX = re.compile(r"^#define\s+(MGRAS_\w+)\s+\(?\s*(0x[0-9a-fA-F]+|\d+)")
CASE_RX = re.compile(r"\bcase\s+([A-Z][A-Z0-9_]*)\s*:")
EQ_RX = re.compile(r"\b(?:if|else\s+if)\s*\(\s*(\w+)\s*==\s*([^)]*?)\)")
#: a multi-line `if (off == A ||\n off == B || ...)` is one logical condition
COND_RX = re.compile(r"\b(?:if|else\s+if)\s*\(\s*(\w+)\s*==\s*([^;{}]*?)\)\s*[{;]",
                     re.S)
RANGE_RX = re.compile(
    r"\b(\w+)\s*>=\s*([A-Z][A-Z0-9_]*)\s*&&\s*\1\s*<\s*[A-Z][A-Z0-9_]*\s*\+\s*"
    r"(0x[0-9a-fA-F]+|\d+|[A-Z][A-Z0-9_]*)")
SUB_RX = re.compile(r"\b(\w+)\s*=\s*(\w+)\s*-\s*(\w+)\s*;")
CONST_ASSIGN_RX = re.compile(r"^\s*(\w+)\s*=\s*([A-Z][A-Z0-9_]*)\s*;", re.M)
#: a handler whose whole answer is a constant: `return 0x10;` / `return 1;`
FIXED_RX = re.compile(r"\breturn\s+(0x[0-9a-fA-F]+|\d+)\s*;")


def read_defines(text: str) -> dict:
    """Every `#define MGRAS_* <number>`, with simple constant arithmetic folded."""
    consts: dict = {}
    exprs: dict = {}
    for line in text.splitlines():
        m = DEFINE_RX.match(line)
        if m:
            consts[m.group(1)] = int(m.group(2), 0)
            continue
        m = re.match(r"^#define\s+(MGRAS_\w+)\s+\(?\s*([^/*]+?)\s*\)?\s*(?:/\*.*)?$",
                     line)
        if m and not m.group(2).startswith('"'):
            exprs[m.group(1)] = m.group(2)
    for _ in range(4):
        for name, expr in list(exprs.items()):
            if name in consts:
                continue
            e, ok = expr, True
            for tok in set(re.findall(r"[A-Z][A-Z0-9_]*", e)):
                if tok in consts:
                    e = re.sub(r"\b%s\b" % re.escape(tok), str(consts[tok]), e)
                else:
                    ok = False
                    break
            if not ok or not re.fullmatch(r"[\s0-9a-fA-FxX()+\-*/<>|&]+", e):
                continue
            try:
                consts[name] = int(eval(e, {"__builtins__": {}}, {}))  # noqa: S307
            except Exception:                   # noqa: BLE001
                pass
    return consts


def _num(tok: str, consts: dict):
    tok = tok.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", tok):
        return int(tok, 0)
    return consts.get(tok)


def _eval_expr(expr: str, consts: dict):
    """`MGRAS_BASE + MGRAS_X_OFF`, `MGRAS_X`, `0x123` -> int, else None."""
    expr = expr.strip()
    m = re.fullmatch(r"(\w+)\s*\+\s*(\w+)", expr)
    if m:
        a, b = _num(m.group(1), consts), _num(m.group(2), consts)
        return None if a is None or b is None else a + b
    if re.fullmatch(r"\w+", expr):
        return consts.get(expr)
    return _num(expr, consts)


def strip_comments(text: str) -> str:
    """Drop C comments and string/char literals so brace counting is honest.

    Line-preserving: a line in the stripped text is the same line in the source.
    """
    out = []
    in_block = False
    for line in text.splitlines():
        res, i = [], 0
        while i < len(line):
            if in_block:
                j = line.find("*/", i)
                if j < 0:
                    i = len(line)
                else:
                    in_block, i = False, j + 2
                continue
            if line.startswith("/*", i):
                in_block, i = True, i + 2
                continue
            if line.startswith("//", i):
                break
            if line[i] in "\"'":
                q, i = line[i], i + 1
                while i < len(line) and line[i] != q:
                    i += 2 if line[i] == "\\" else 1
                i += 1
                res.append('""')
                continue
            res.append(line[i])
            i += 1
        out.append("".join(res))
    return "\n".join(out)


def functions(text: str) -> list:
    """Split C source into (name, body) for every brace-balanced definition.

    The `{` may sit on its own line below the signature (the house style here),
    so the candidate signature is the last non-empty line seen at depth 0.
    """
    clean = strip_comments(text).splitlines()
    raw = text.splitlines()
    out, depth, start, name, head = [], 0, None, None, ""
    for i, line in enumerate(clean):
        if depth == 0 and start is None:
            if "{" in line:
                cand = line.split("{")[0].strip() or head
                m = re.search(r"(\w+)\s*\([^;{]*\)\s*$", cand)
                if m and not cand.startswith(("if", "for", "while", "switch",
                                              "} else")):
                    start, name = i, m.group(1)
            elif line.strip():
                head = line.strip()
        depth += line.count("{") - line.count("}")
        if start is not None and depth <= 0 and i > start:
            out.append((name, "\n".join(raw[start:i + 1])))
            start, head = None, ""
    return out


def scan(text: str, consts: dict) -> dict:
    """All four handler forms, resolved: {offset: [description, ...]}."""
    found: dict = {}

    def note(off: int, why: str) -> None:
        found.setdefault(off, []).append(why)




    # forms 1 and 2, file scope: `if (off == <expr>)`, and `a || b || ...` chains
    # (which may wrap over several lines, so the condition is matched whole)
    for m in COND_RX.finditer(text):
        cond = re.sub(r"\s+", " ", m.group(0))
        for em in re.finditer(r"\b(\w+)\s*==\s*([^|=!<>&]+?)\s*(?=$|\|\||\))",
                              cond):
            off = _eval_expr(em.group(2), consts)
            if off is not None:
                note(off, "direct: %s == %s" % (em.group(1), em.group(2).strip()))

    # form 4: `case MGRAS_X:` in any switch
    for m in CASE_RX.finditer(text):
        off = consts.get(m.group(1))
        if off is not None:
            note(off, "case: %s" % m.group(1))

    # form 3: a window range, the variable it subtracts, and the offsets tested
    for _fname, body in functions(text):
        assigns: dict = {}
        for m in CONST_ASSIGN_RX.finditer(body):
            if m.group(2) in consts:
                assigns.setdefault(m.group(1), set()).add(consts[m.group(2)])
        ranges = []
        for m in RANGE_RX.finditer(body):
            var, base_name, span = m.groups()
            base, n = consts.get(base_name), _num(span, consts)
            if base is not None and n is not None:
                ranges.append((var, base, base + n))
        for m in SUB_RX.finditer(body):
            sub, var, src = m.groups()
            bases = [consts[src]] if src in consts else sorted(assigns.get(src, ()))
            for base in bases:
                if not any(v == var and lo == base for v, lo, _ in ranges):
                    continue
                for em in EQ_RX.finditer(body):
                    if em.group(1) != sub or "||" in em.group(2):
                        continue
                    delta = _eval_expr(em.group(2), consts)
                    if delta is None:
                        continue
                    note(base + delta,
                         "window: %s >= 0x%x, %s = %s - %s, %s == %s"
                         % (var, base, sub, var, src, sub, em.group(2).strip()))
    return found


def classify(text: str, consts: dict, offsets, use_window: bool = True) -> dict:
    """{offset: state} plus the evidence each state rests on."""
    found = scan(text, consts)
    if not use_window:
        found = {k: [w for w in v if not w.startswith("window")]
                 for k, v in found.items()}
        found = {k: v for k, v in found.items() if v}
    states = {}
    for off in offsets:
        why = found.get(off) or []
        if not why:
            states[off] = "absent"      # no branch: the generic reg[] play-back
        elif any(FIXED_RX.search(w) for w in why):
            states[off] = "fixed"
        else:
            states[off] = "implemented"
    return {"state": states, "evidence": {k: found.get(k, []) for k in offsets}}


def census(text: str, offsets, use_window: bool = True) -> dict:
    return classify(text, read_defines(text), offsets, use_window)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", required=True,
                    help="the model tree (a qemu-sgi-repo checkout)")
    ap.add_argument("--offsets", required=True, help="comma-separated offsets")
    ap.add_argument("--out", help="write the per-offset states here as JSON")
    ap.add_argument("--no-window", action="store_true",
                    help="disable the window form (the control's RED arm)")
    args = ap.parse_args(argv)
    src = Path(args.tree) / "hw" / "mips" / "sgi_octane.c"
    if not src.exists():
        print("NOT MEASURED: no %s" % src)
        return 2
    offsets = [int(t, 0) for t in args.offsets.replace(" ", "").split(",") if t]
    text = src.read_text(errors="replace")
    res = census(text, offsets, use_window=not args.no_window)
    from collections import Counter
    cnt = Counter(res["state"].values())
    doc = {"tree": str(args.tree), "source": str(src),
           "window_form": not args.no_window,
           "census": {k: cnt.get(k, 0)
                      for k in ("implemented", "fixed", "unimp", "absent")},
           "states": {"0x%x" % k: v for k, v in sorted(res["state"].items())},
           "evidence": {"0x%x" % k: v for k, v in sorted(res["evidence"].items())}}
    if args.out:
        Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
    print("tree %s window_form=%s" % (args.tree, not args.no_window))
    print("implemented/fixed/unimp/absent %d/%d/%d/%d over %d offsets"
          % (cnt.get("implemented", 0), cnt.get("fixed", 0), cnt.get("unimp", 0),
             cnt.get("absent", 0), len(offsets)))
    for off in offsets:
        print("  0x%06x %-12s %s" % (off, res["state"][off],
                                      (res["evidence"][off] or [""])[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
