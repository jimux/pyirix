"""toolchain — locate MIPS cross-tools and gdb on this host.

The bare-metal MIPS cross-toolchain is installed under a fixed prefix in the
dev container (/opt/cross/mips-elf/bin) and, on some hosts, under
~/cross/mips-elf/bin; distributions also package the same tools as
mips-linux-gnu-*.  macOS Homebrew has **no MIPS assembler**, but a downloaded
bare-metal toolchain at ~/cross/mips-elf satisfies the mips-elf-* names, and its
keg-only, host-targeted binutils (gnm/gobjdump/gsize) can still *read*
big-endian MIPS ELF.

gdb is `gdb-multiarch` on Linux and plain `gdb` on macOS — resolve via
:func:`resolve_gdb` so callers are platform-agnostic.
"""
from __future__ import annotations

import os
import shutil

# Explicit shim prefixes tried before PATH, in order.
_MIPS_PREFIXES = (
    os.path.expanduser("~/cross/mips-elf/bin/mips-elf-"),
    "/opt/cross/mips-elf/bin/mips-elf-",
)

# PATH name variants for a tool suffix (e.g. "as" -> mips-elf-as, …).
_MIPS_NAME_VARIANTS = ("mips-elf-{t}", "mips64-elf-{t}", "mips-linux-gnu-{t}")

# macOS Homebrew binutils is `g`-prefixed and keg-only. It cannot ASSEMBLE MIPS
# (it is host-targeted), but it reads MIPS-BE ELF fine, so only offer it for the
# read-only tools.
_BREW_G = {
    "nm": "gnm", "objdump": "gobjdump", "size": "gsize",
    "strip": "gstrip", "readelf": "greadelf", "objcopy": "gobjcopy",
}
_BREW_PREFIXES = ("/opt/homebrew/opt/binutils/bin/", "/usr/local/opt/binutils/bin/")


def find_mips_tool(tool: str):
    """Return a path to a MIPS-capable *tool*, or None.

    *tool* is a bare binutils suffix: ``as``, ``objcopy``, ``nm``, ``objdump``,
    ``size``, ``ld``, ``gcc``, ``strip``, ``readelf``.  The host-targeted macOS
    Homebrew ``g*`` tools are only considered for the read-only suffixes (they
    cannot assemble MIPS).
    """
    for prefix in _MIPS_PREFIXES:
        path = prefix + tool
        if os.path.exists(path):
            return path
    for variant in _MIPS_NAME_VARIANTS:
        found = shutil.which(variant.format(t=tool))
        if found:
            return found
    gname = _BREW_G.get(tool)
    if gname:
        for prefix in _BREW_PREFIXES:
            if os.path.exists(prefix + gname):
                return prefix + gname
        found = shutil.which(gname)
        if found:
            return found
        found = shutil.which("llvm-" + tool)
        if found:
            return found
    return None


def resolve_gdb() -> str:
    """Return a usable gdb path, or raise with an actionable message."""
    for name in ("gdb-multiarch", "gdb"):
        found = shutil.which(name)
        if found:
            return found
    raise RuntimeError(
        "no gdb found on PATH: install gdb-multiarch (Linux) or gdb "
        "(macOS: `brew install gdb`, then codesign it)")
