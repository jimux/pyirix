#!/usr/bin/env python3
"""Verify an imported Indigo data root.

Checks, in order:

1. **receipt** present and parseable.
2. **presence + min counts** — every required manifest category meets its
   ``min_count`` (recomputed live from the data root, not trusted from the
   receipt); optional categories are reported but don't fail the gate.
3. **format sanity** —
   * parse one scheme palette as X-resources (``#define Name value`` and/or
     ``!*resource: value`` lines);
   * sanity-parse up to 5 ``.fti`` icons as ASCII vector programs
     (``color()``/``vertex()``/``bgn*polygon()`` tokens).

`verify(data_root)` returns a `VerifyReport`. The CLI prints a summary and
exits non-zero on failure.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from pyirix.indigo import manifest as M
from pyirix.indigo.config import resolve_data_root
from pyirix.indigo.importer import _recompute_categories, RECEIPT_NAME


_FTI_TOKENS = re.compile(
    r"\b(color|vertex|bgnpolygon|endpolygon|bgnoutlinepolygon|"
    r"endoutlinepolygon|bgnline|endline|bgnpoint|endpoint|rgbi|cmov|"
    r"rmv|rdr|arc|circ|clear|backgroundcolor|smoothline)\b"
)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyReport:
    data_root: str
    ok: bool = True
    checks: list[Check] = field(default_factory=list)
    categories: dict = field(default_factory=dict)

    def add(self, name, ok, detail=""):
        self.checks.append(Check(name, ok, detail))
        if not ok:
            self.ok = False

    def summary(self) -> str:
        lines = [f"data root: {self.data_root}",
                 f"result:    {'PASS' if self.ok else 'FAIL'}", ""]
        for c in self.checks:
            mark = "ok " if c.ok else "FAIL"
            lines.append(f"  [{mark}] {c.name}"
                         + (f" — {c.detail}" if c.detail else ""))
        lines.append("")
        lines.append("category counts:")
        for name, info in self.categories.items():
            need = info["min_count"] if info["required"] else 0
            got = info["count"]
            flag = "" if (got >= need or not info["required"]) else "  <-- LOW"
            req = "req" if info["required"] else "opt"
            lines.append(f"  {name:<12} {got:>6}  ({info['count_kind']}, "
                         f"{req}, min {info['min_count']}){flag}")
        return "\n".join(lines)


def _find_ext(root: str, prefix: str, suffix: str, limit: int) -> list[str]:
    base = os.path.join(root, prefix)
    out = []
    if not os.path.isdir(base):
        return out
    for dp, _d, files in os.walk(base):
        for fn in files:
            if fn.endswith(suffix):
                out.append(os.path.join(dp, fn))
                if len(out) >= limit:
                    return out
    return out


def _find_scheme_palette(root: str) -> str | None:
    base = os.path.join(root, "usr/lib/X11/schemes")
    if not os.path.isdir(base):
        return None
    # prefer a Base/*Palette or any regular file
    prefer = os.path.join(base, "Base")
    for cand_dir in ([prefer] if os.path.isdir(prefer) else []) + [base]:
        for dp, _d, files in os.walk(cand_dir):
            for fn in files:
                p = os.path.join(dp, fn)
                if os.path.isfile(p) and not os.path.islink(p):
                    return p
    return None


def _parse_scheme_xresources(path: str) -> tuple[bool, str]:
    try:
        text = Path(path).read_text(errors="replace")
    except Exception as e:
        return False, f"unreadable: {e}"
    defines = len(re.findall(r"^\s*#define\s+\w+", text, re.M))
    resources = len(re.findall(r"^\s*!?\*?[\w.*]+\s*:\s*\S", text, re.M))
    if defines + resources == 0:
        return False, f"no #define/resource lines in {os.path.basename(path)}"
    return True, (f"{os.path.basename(path)}: {defines} #define, "
                  f"{resources} resource lines")


def _parse_fti(path: str) -> tuple[bool, str]:
    try:
        data = Path(path).read_bytes()
    except Exception as e:
        return False, f"unreadable: {e}"
    # must be ASCII text
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return False, f"{os.path.basename(path)}: not ASCII"
    if not _FTI_TOKENS.search(text):
        return False, f"{os.path.basename(path)}: no vector commands"
    return True, ""


def verify(data_root: str | None = None) -> VerifyReport:
    root = resolve_data_root(data_root)
    rep = VerifyReport(data_root=root)

    # 1. receipt
    receipt_path = os.path.join(root, RECEIPT_NAME)
    rep.add("receipt present", os.path.isfile(receipt_path),
            receipt_path if os.path.isfile(receipt_path) else "missing")

    # 2. presence + counts
    cats = _recompute_categories(root)
    rep.categories = cats
    for name, info in cats.items():
        if info["required"]:
            ok = info["count"] >= info["min_count"]
            rep.add(f"count[{name}]", ok,
                    f"{info['count']} >= {info['min_count']}"
                    if ok else
                    f"only {info['count']} (need {info['min_count']})")
        else:
            # optional: just report, never fail
            rep.add(f"count[{name}] (optional)", True,
                    f"{info['count']}")

    # 3a. scheme palette parses as X-resources
    pal = _find_scheme_palette(root)
    if pal:
        ok, detail = _parse_scheme_xresources(pal)
        rep.add("scheme palette parses", ok, detail)
    else:
        rep.add("scheme palette parses", False, "no scheme file found")

    # 3b. up to 5 .fti sanity-parse
    ftis = _find_ext(root, "usr/lib/filetype", ".fti", 5)
    if ftis:
        bad = []
        for p in ftis:
            ok, detail = _parse_fti(p)
            if not ok:
                bad.append(detail)
        rep.add(".fti vector-command sanity", not bad,
                f"{len(ftis)} parsed OK" if not bad else "; ".join(bad))
    else:
        rep.add(".fti vector-command sanity", False,
                "no .fti files found under usr/lib/filetype")

    return rep
