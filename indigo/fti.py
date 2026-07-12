#!/usr/bin/env python3
"""pyirix.indigo.fti -- a pure-Python parser + rasterizer for the SGI IRIX
``.fti`` icon vector language.

This is a *verification / authoring* harness, NOT the runtime rendering path.
On real IRIX, ``.fti`` sources are lex/yacc-compiled to instruction bytecode
*inside* the compiled FTR database (``.otr``) by ``fftr`` at build time, and the
desktop (fm / libimdFtrIcon) renders that bytecode -- it never parses ``.fti``
text at runtime (confirmed in progress_notes/indigo_linux/00-README, fftr row).
We use this harness to (a) validate that our understanding of the ``.fti``
grammar covers the whole corpus, (b) preview icons as PNGs for design review,
and (c) author our own original genre icons and check they are style-coherent
and syntactically identical to the SGI corpus subset.

The ``.fti`` language (derived empirically from ~1860 ASCII corpus files -- see
``progress_notes/indigo_linux/13-fti-harness-icons.md`` for the full command
census):

  Drawing state
    color(<sym|index>)          set the current drawing color

  Block primitives (open with bgn*, add vertex(x,y), close with end*)
    bgnpolygon() .. endpolygon()                        filled polygon
    bgnoutlinepolygon() .. endoutlinepolygon(<color>)   filled + outlined
    bgnline() .. endline()                              open polyline
    bgnclosedline() .. endclosedline()                  closed polyline (no fill)
    bgnpoint() .. endpoint()                            points

  Immediate primitives (path built by move/draw verbs, then closed)
    pmv(x,y) pdr(x,y) .. pclos()          filled polygon
    pmv(x,y) pdr(x,y) .. bclos(<color>)   filled + outlined polygon
    move(x,y) draw(x,y) ..                open polyline (implicit flush)

Coordinates live on a ~0..100 canvas with the GL/maths convention (y grows
UPward); the rasterizer flips y for screen space.  ``#`` starts a comment to
end-of-line; ``;`` and ``,`` are insignificant separators.

Colors are either the three scheme-symbolic names that occur in the corpus
(``iconcolor``, ``outlinecolor``, ``shadowcolor``) or an integer palette index.
The real symbolic->RGB mapping is per-scheme and resolved by the runtime; here
we use a documented approximation of the classic Indigo Magic look (see
``DEFAULT_PALETTE``).  The real scheme mapping is future work (Track 1 schemes).
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

RGB = Tuple[int, int, int]
RGBA = Tuple[int, int, int, int]

# --------------------------------------------------------------------------
# Grammar
# --------------------------------------------------------------------------

# Every command keyword observed in the corpus, plus the primitives they pair
# with.  A strict-but-listed set: an unknown keyword is reported (so grammar
# surprises surface) and, in lenient mode, skipped rather than fatal.
BLOCK_OPEN = {
    "bgnpolygon": "poly_fill",
    "bgnoutlinepolygon": "poly_outline",
    "bgnline": "line",
    "bgnclosedline": "closedline",
    "bgnpoint": "point",
}
BLOCK_CLOSE = {
    "endpolygon": "poly_fill",
    "endoutlinepolygon": "poly_outline",
    "endline": "line",
    "endclosedline": "closedline",
    "endpoint": "point",
}
KNOWN_COMMANDS = (
    set(BLOCK_OPEN) | set(BLOCK_CLOSE)
    | {"color", "vertex", "pmv", "pdr", "pclos", "bclos", "move", "draw"}
)


class FtiError(Exception):
    """Raised on a genuinely malformed .fti (in strict mode)."""


@dataclass
class Command:
    name: str
    args: List[str]
    line: int


# Op kinds emitted by the parser -- a flat, render-ready display list.
OP_POLY_FILL = "poly_fill"        # fill only
OP_POLY_OUTLINE = "poly_outline"  # fill + outline
OP_LINE = "line"                  # open polyline
OP_CLOSEDLINE = "closedline"      # closed polyline, no fill
OP_POINT = "point"                # points


@dataclass
class DrawOp:
    kind: str
    verts: List[Tuple[float, float]]
    color: "Color"                       # fill / stroke color
    outline: Optional["Color"] = None    # outline color for poly_outline


@dataclass
class Color:
    """A resolved-later color reference: a symbolic name or a palette index."""
    symbol: Optional[str] = None
    index: Optional[int] = None

    def rgb(self, palette: "Palette") -> RGB:
        return palette.resolve(self)

    def __repr__(self):
        return (f"Color(sym={self.symbol!r})" if self.symbol is not None
                else f"Color(idx={self.index})")


# --------------------------------------------------------------------------
# Tokenizer + parser
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"""
      \#[^\n]*                 # comment to EOL
    | [A-Za-z_][A-Za-z0-9_]*   # identifier
    | [()]                     # parens
    | -?\.?\d[\w.+-]*          # a number-ish run (atof-style, trailing junk ok)
    | [;,]                     # separators
    | \s+                      # whitespace
""", re.VERBOSE)


def tokenize(text: str) -> List[Tuple[str, int]]:
    """Return (token, lineno) for identifiers, parens, numbers and separators;
    comments and whitespace are dropped."""
    out: List[Tuple[str, int]] = []
    line = 1
    i = 0
    n = len(text)
    while i < n:
        m = _TOKEN_RE.match(text, i)
        if not m:
            # a stray character (e.g. an operator) -- consume one, ignore.
            if text[i] == "\n":
                line += 1
            i += 1
            continue
        tok = m.group(0)
        i = m.end()
        nl = tok.count("\n")
        if tok[0] == "#" or tok.isspace() or tok in ",;":
            line += nl
            continue
        out.append((tok, line))
        line += nl
    return out


def _atof(tok: str) -> float:
    """C atof-style: parse a leading float, ignore trailing junk."""
    m = re.match(r"[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?", tok)
    return float(m.group(0)) if m else 0.0


def parse_commands(text: str, *, strict: bool = False) -> Tuple[List[Command], List[str]]:
    """Tokenize into ``name(args...)`` commands.  Returns (commands, warnings)."""
    toks = tokenize(text)
    cmds: List[Command] = []
    warnings: List[str] = []
    i = 0
    n = len(toks)
    while i < n:
        name, line = toks[i]
        if not (name[0].isalpha() or name[0] == "_"):
            msg = f"line {line}: unexpected token {name!r}"
            if strict:
                raise FtiError(msg)
            warnings.append(msg)
            i += 1
            continue
        i += 1
        if i >= n or toks[i][0] != "(":
            msg = f"line {line}: command {name!r} not followed by '('"
            if strict:
                raise FtiError(msg)
            warnings.append(msg)
            continue
        i += 1  # consume '('
        args: List[str] = []
        while i < n and toks[i][0] != ")":
            args.append(toks[i][0])
            i += 1
        if i >= n:
            msg = f"line {line}: command {name!r} unterminated '('"
            if strict:
                raise FtiError(msg)
            warnings.append(msg)
            break
        i += 1  # consume ')'
        cmds.append(Command(name, args, line))
        if name not in KNOWN_COMMANDS:
            msg = f"line {line}: unknown command {name!r}"
            if strict:
                raise FtiError(msg)
            warnings.append(msg)
    return cmds, warnings


def _mk_color(arg: str) -> Color:
    a = arg.strip()
    if a and (a[0] in "-+." or a[0].isdigit()):
        return Color(index=int(round(_atof(a))))
    return Color(symbol=a)


@dataclass
class FtiIcon:
    """A parsed .fti icon: a flat display list plus metadata."""
    ops: List[DrawOp] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    path: Optional[str] = None

    @property
    def bbox(self) -> Tuple[float, float, float, float]:
        xs: List[float] = []
        ys: List[float] = []
        for op in self.ops:
            for (x, y) in op.verts:
                xs.append(x)
                ys.append(y)
        if not xs:
            return (0.0, 0.0, 100.0, 100.0)
        return (min(xs), min(ys), max(xs), max(ys))


def parse(text: str, *, strict: bool = False, path: Optional[str] = None) -> FtiIcon:
    """Parse .fti source into a render-ready :class:`FtiIcon`."""
    cmds, warnings = parse_commands(text, strict=strict)
    ops: List[DrawOp] = []
    cur = Color(symbol="iconcolor")          # default drawing color
    block: Optional[str] = None              # active bgn* block kind
    verts: List[Tuple[float, float]] = []
    # immediate-mode path state (pmv/pdr, move/draw)
    imm_kind: Optional[str] = None           # "poly" or "line"
    imm_verts: List[Tuple[float, float]] = []

    def flush_line_path():
        nonlocal imm_kind, imm_verts
        if imm_kind == "line" and len(imm_verts) >= 2:
            ops.append(DrawOp(OP_LINE, imm_verts[:], cur))
        imm_kind = None
        imm_verts = []

    def xy(args: Sequence[str], line: int) -> Tuple[float, float]:
        if len(args) < 2:
            warnings.append(f"line {line}: vertex/move needs 2 args, got {args}")
            a = _atof(args[0]) if args else 0.0
            return (a, 0.0)
        return (_atof(args[0]), _atof(args[1]))

    for c in cmds:
        name = c.name
        if name == "color":
            # a color() also ends any pending open move/draw polyline
            flush_line_path()
            cur = _mk_color(c.args[0]) if c.args else Color(symbol="iconcolor")
        elif name in BLOCK_OPEN:
            flush_line_path()
            block = BLOCK_OPEN[name]
            verts = []
        elif name in BLOCK_CLOSE:
            kind = BLOCK_CLOSE[name]
            if kind == "poly_outline":
                oc = _mk_color(c.args[0]) if c.args else Color(symbol="outlinecolor")
                ops.append(DrawOp(OP_POLY_OUTLINE, verts[:], cur, outline=oc))
            elif kind == "poly_fill":
                ops.append(DrawOp(OP_POLY_FILL, verts[:], cur))
            elif kind == "line":
                ops.append(DrawOp(OP_LINE, verts[:], cur))
            elif kind == "closedline":
                ops.append(DrawOp(OP_CLOSEDLINE, verts[:], cur))
            elif kind == "point":
                ops.append(DrawOp(OP_POINT, verts[:], cur))
            block = None
            verts = []
        elif name == "vertex":
            verts.append(xy(c.args, c.line))
        elif name == "pmv":
            flush_line_path()
            imm_kind = "poly"
            imm_verts = [xy(c.args, c.line)]
        elif name == "pdr":
            if imm_kind != "poly":
                imm_kind = "poly"
                imm_verts = []
            imm_verts.append(xy(c.args, c.line))
        elif name == "pclos":
            if len(imm_verts) >= 3:
                ops.append(DrawOp(OP_POLY_FILL, imm_verts[:], cur))
            imm_kind = None
            imm_verts = []
        elif name == "bclos":
            oc = _mk_color(c.args[0]) if c.args else Color(symbol="outlinecolor")
            if len(imm_verts) >= 3:
                ops.append(DrawOp(OP_POLY_OUTLINE, imm_verts[:], cur, outline=oc))
            imm_kind = None
            imm_verts = []
        elif name == "move":
            flush_line_path()
            imm_kind = "line"
            imm_verts = [xy(c.args, c.line)]
        elif name == "draw":
            if imm_kind != "line":
                imm_kind = "line"
                imm_verts = []
            imm_verts.append(xy(c.args, c.line))
        # unknown commands were already warned about in parse_commands
    flush_line_path()

    return FtiIcon(ops=ops, warnings=warnings, path=path)


# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

# The classic 16-entry IRIS GL default colormap (indices 0..15).  Indices 0..7
# are the canonical GL colors; 8..15 are the standard dim/second bank that IRIX
# fticons use for shading (e.g. flight.fti color(15) = light grey ring,
# color(7) = white cockpit).  These are a documented approximation.
_IRIS16: List[RGB] = [
    (0, 0, 0),        # 0 black
    (255, 0, 0),      # 1 red
    (0, 255, 0),      # 2 green
    (255, 255, 0),    # 3 yellow
    (0, 0, 255),      # 4 blue
    (255, 0, 255),    # 5 magenta
    (0, 255, 255),    # 6 cyan
    (255, 255, 255),  # 7 white
    (85, 85, 85),     # 8  dim grey
    (198, 113, 113),  # 9  dim red
    (113, 198, 113),  # 10 dim green
    (204, 204, 127),  # 11 dim yellow
    (113, 113, 198),  # 12 dim blue
    (198, 113, 198),  # 13 dim magenta
    (113, 198, 198),  # 14 dim cyan
    (200, 200, 200),  # 15 light grey
]


@dataclass
class Palette:
    """Symbolic + indexed color resolution.

    The symbolic values approximate the default Indigo Magic scheme, grounded in
    the corpus scheme files (``schemes/Base/ImdPalette`` etc.):
      * iconcolor   -- the light neutral icon body (Imd*IconColor family
                       #b6b6aa / #d1d1c9 -> a warm light grey).
      * outlinecolor-- the black hairline outline the desktop draws.
      * shadowcolor -- the offset drop-shadow silhouette (a dark grey).
    The exact per-scheme mapping is resolved at runtime on IRIX and is deferred
    to the Track-1 schemes work; these are chosen to read correctly at 32-64px.
    """
    symbolic: dict = field(default_factory=lambda: {
        "iconcolor": (196, 196, 188),
        "outlinecolor": (0, 0, 0),
        "shadowcolor": (78, 78, 74),
        # extra scheme names not seen in the corpus but valid targets, mapped
        # to sensible defaults so our own icons (and future imports) render:
        "highlightcolor": (255, 255, 255),
        "selectcolor": (135, 170, 202),   # AlternateBackground5 blue
        "referencecolor": (86, 128, 171),
        "readonlyiconcolor": (182, 182, 170),
    })

    def resolve(self, c: Color) -> RGB:
        if c.symbol is not None:
            key = c.symbol.lower()
            if key in self.symbolic:
                return self.symbolic[key]
            # unknown symbol -> iconcolor (documented fallback)
            return self.symbolic["iconcolor"]
        idx = c.index if c.index is not None else 0
        if 0 <= idx < len(_IRIS16):
            return _IRIS16[idx]
        return self._extended(idx)

    @staticmethod
    def _extended(idx: int) -> RGB:
        """Indices outside 0..15 (incl. the large negatives used by the O2
        photo-realistic icons) index a per-scheme *dynamic* colormap we do not
        have here.  We map them to a stable, monotonic warm-grey ramp keyed on
        the index so those icons render as coherent shaded images rather than
        noise -- an explicit approximation until the scheme colormap lands."""
        # spread |idx| across a 0..1 ramp; bias warm to match SGI icon tone
        t = (abs(idx) % 256) / 255.0
        lo, hi = 40, 225
        v = int(lo + (hi - lo) * t)
        return (min(255, v + 12), v, max(0, v - 10))


DEFAULT_PALETTE = Palette()

# Background used for contact sheets: the real Icon Catalog panel colour
# (AlternateBackground5, #87aaca) so icons sit on an authentic ground.
PANEL_BG: RGBA = (135, 170, 202, 255)


# --------------------------------------------------------------------------
# Rasterizer (PIL)
# --------------------------------------------------------------------------

def _require_pil():
    try:
        from PIL import Image, ImageDraw  # noqa: F401
        return Image, ImageDraw
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Pillow (PIL) is required for .fti rasterization; "
            "install with `pip install pillow`") from e


def render(icon: FtiIcon, size: int = 48, *,
           palette: Palette = DEFAULT_PALETTE,
           bg: Optional[RGBA] = None,
           supersample: int = 4,
           margin: float = 4.0):
    """Rasterize *icon* to a ``size``x``size`` PIL RGBA image.

    ``bg`` None -> transparent.  Rendering is supersampled then box-filtered
    down for smooth edges.  The 0..100 canvas maps into the image with a small
    ``margin`` (canvas units) so hairline outlines at the edge are not clipped.
    """
    Image, ImageDraw = _require_pil()
    S = max(1, int(supersample))
    W = size * S
    base = bg if bg is not None else (0, 0, 0, 0)
    img = Image.new("RGBA", (W, W), base)
    drw = ImageDraw.Draw(img)

    span = 100.0 + 2 * margin

    def tx(x: float) -> float:
        return (x + margin) / span * W

    def ty(y: float) -> float:
        # flip: fti y grows up, image y grows down
        return (1.0 - (y + margin) / span) * W

    ow = max(1, int(round(S * max(1.0, size / 44.0))))  # outline width in px

    def pts(vs):
        return [(tx(x), ty(y)) for (x, y) in vs]

    for op in icon.ops:
        if not op.verts:
            continue
        p = pts(op.verts)
        col = op.color.rgb(palette)
        fill = (col[0], col[1], col[2], 255)
        if op.kind in (OP_POLY_FILL, OP_POLY_OUTLINE):
            if len(p) >= 3:
                drw.polygon(p, fill=fill)
            if op.kind == OP_POLY_OUTLINE and op.outline is not None:
                oc = op.outline.rgb(palette)
                ocf = (oc[0], oc[1], oc[2], 255)
                drw.line(p + [p[0]], fill=ocf, width=ow, joint="curve")
        elif op.kind == OP_LINE:
            if len(p) >= 2:
                drw.line(p, fill=fill, width=ow, joint="curve")
        elif op.kind == OP_CLOSEDLINE:
            if len(p) >= 2:
                drw.line(p + [p[0]], fill=fill, width=ow, joint="curve")
        elif op.kind == OP_POINT:
            r = max(1, ow)
            for (px, py) in p:
                drw.ellipse([px - r, py - r, px + r, py + r], fill=fill)

    if S != 1:
        img = img.resize((size, size), Image.LANCZOS)
    return img


def render_file(path: str, size: int = 48, **kw):
    with open(path, "r", errors="replace") as f:
        icon = parse(f.read(), path=path)
    return render(icon, size, **kw), icon


# --------------------------------------------------------------------------
# Corpus enumeration + contact sheets
# --------------------------------------------------------------------------

def is_ascii_fti(path: str) -> bool:
    """Cheap check: a real ASCII vector .fti (not a compiled/raster/empty one)."""
    try:
        if os.path.getsize(path) == 0:
            return False
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    if b"\x00" in head:
        return False
    # must contain at least one recognizable command token
    try:
        txt = head.decode("ascii", "strict")
    except UnicodeDecodeError:
        return False
    return any(k in txt for k in ("color(", "vertex(", "bgn", "pmv(", "move("))


def find_corpus_fti(roots: Sequence[str]) -> List[str]:
    """Find all ``filetype/**/iconlib/*.fti`` files under the given roots."""
    out: List[str] = []
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            if os.path.basename(dirpath) != "iconlib":
                continue
            if "filetype" not in dirpath:
                continue
            for fn in files:
                if fn.endswith(".fti"):
                    out.append(os.path.join(dirpath, fn))
    return sorted(set(out))


def contact_sheet(paths: Sequence[str], out_path: str, *,
                  cell: int = 64, cols: int = 12,
                  palette: Palette = DEFAULT_PALETTE,
                  bg: RGBA = PANEL_BG, label: bool = True,
                  gap: int = 6):
    """Render *paths* into a labelled grid PNG at *out_path*."""
    Image, ImageDraw = _require_pil()
    try:
        from PIL import ImageFont
        font = ImageFont.load_default()
    except Exception:
        font = None
    n = len(paths)
    cols = max(1, cols)
    rows = (n + cols - 1) // cols
    lab_h = 12 if label else 0
    cw = cell + gap
    ch = cell + gap + lab_h
    sheet = Image.new("RGBA", (cols * cw + gap, rows * ch + gap), (60, 60, 66, 255))
    drw = ImageDraw.Draw(sheet)
    for i, p in enumerate(paths):
        r, cidx = divmod(i, cols)
        x0 = gap + cidx * cw
        y0 = gap + r * ch
        try:
            with open(p, "r", errors="replace") as f:
                icon = parse(f.read(), path=p)
            im = render(icon, cell, palette=palette, bg=bg)
        except Exception as e:  # keep the sheet building even on a bad file
            im = Image.new("RGBA", (cell, cell), (120, 40, 40, 255))
            ImageDraw.Draw(im).text((2, 2), "ERR", fill=(255, 255, 255))
            icon = None
        sheet.paste(im, (x0, y0), im)
        if label and font is not None:
            name = os.path.basename(p)
            if name.endswith(".fti"):
                name = name[:-4]
            if len(name) > 12:
                name = name[:11] + "…"
            drw.text((x0, y0 + cell + 1), name, fill=(230, 230, 230), font=font)
    sheet.save(out_path)
    return out_path
