"""Display-gamma adaptation for imported IRIX color assets.

IRIX color assets are authored for a gamma-corrected display (the Newport
applies a hardware LUT, 1.7 by default), while modern X servers (Xephyr,
Xwayland) are linear. Two cases:

1. **Scheme palettes need NO transform** — SGI authored per-gamma variants
   inside every ColorPalette (``#ifdef GAMMA_1_0 / GAMMA_1_7 / GAMMA_2_4``).
   On a linear display, preprocess schemes with ``-DGAMMA_1_0`` (NOT the
   IRIX-default ``-DGAMMA_1_7``). Verified: BasicBackground is #c1c1c1 (193)
   in the 1.7 variant and #d9d9d9 (217) in the 1.0 variant — exactly
   ``255*(193/255)**(1/1.7)``.

2. **Everything without variants** (rgb.txt-derived hex in app-defaults,
   colors sampled from IRIX framebuffer dumps) carries pre-LUT values and
   must be gamma-ENCODED for a linear display: ``v' = 255*(v/255)**(1/g)``
   with g=1.7. That is what this module does.

CLI:
    python3 -m pyirix.indigo.gammaenc [--gamma 1.7] [-o OUT] FILE...
    (no -o: writes FILE.gamma alongside; with -o and one FILE: writes OUT;
     with -o DIR and many FILEs: mirrors basenames into DIR)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_GAMMA = 1.7

_HEX_RE = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{12})\b")
_RGBI_RE = re.compile(r"\brgb:([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})\b")


def encode_byte(v: int, gamma: float = DEFAULT_GAMMA) -> int:
    """Gamma-encode one 0-255 channel value for a linear display."""
    if v <= 0:
        return 0
    if v >= 255:
        return 255
    return round(255.0 * (v / 255.0) ** (1.0 / gamma))


def _enc_scaled(v: int, maxv: int, gamma: float) -> int:
    if v <= 0:
        return 0
    if v >= maxv:
        return maxv
    return round(maxv * (v / maxv) ** (1.0 / gamma))


def _sub_hex(m: re.Match, gamma: float) -> str:
    h = m.group(1)
    if len(h) == 3:  # #rgb -> per-nibble channels
        return "#" + "".join("%x" % _enc_scaled(int(c, 16), 15, gamma) for c in h)
    if len(h) == 6:
        return "#" + "".join(
            "%02x" % encode_byte(int(h[i : i + 2], 16), gamma) for i in (0, 2, 4)
        )
    # 12-digit X form: 4 hex digits per channel
    return "#" + "".join(
        "%04x" % _enc_scaled(int(h[i : i + 4], 16), 0xFFFF, gamma) for i in (0, 4, 8)
    )


def _sub_rgbi(m: re.Match, gamma: float) -> str:
    parts = []
    for h in m.groups():
        maxv = 16 ** len(h) - 1
        parts.append(("%0" + str(len(h)) + "x") % _enc_scaled(int(h, 16), maxv, gamma))
    return "rgb:%s/%s/%s" % tuple(parts)


def encode_text(text: str, gamma: float = DEFAULT_GAMMA) -> str:
    """Gamma-encode every #hex and rgb:/ color literal in *text*."""
    text = _HEX_RE.sub(lambda m: _sub_hex(m, gamma), text)
    text = _RGBI_RE.sub(lambda m: _sub_rgbi(m, gamma), text)
    return text


def encode_file(src: Path, dst: Path, gamma: float = DEFAULT_GAMMA) -> int:
    """Encode *src* into *dst*; returns the number of color literals rewritten."""
    text = src.read_text(errors="surrogateescape")
    n = len(_HEX_RE.findall(text)) + len(_RGBI_RE.findall(text))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(encode_text(text, gamma), errors="surrogateescape")
    return n


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    gamma = DEFAULT_GAMMA
    out: Path | None = None
    files: list[Path] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--gamma":
            i += 1
            gamma = float(args[i])
        elif a == "-o":
            i += 1
            out = Path(args[i])
        else:
            files.append(Path(a))
        i += 1
    if not files:
        print(__doc__)
        return 2
    for f in files:
        if out is None:
            dst = f.with_name(f.name + ".gamma")
        elif len(files) == 1 and not out.is_dir():
            dst = out
        else:
            dst = out / f.name
        n = encode_file(f, dst, gamma)
        print(f"{f} -> {dst}: {n} colors encoded (gamma {gamma})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
