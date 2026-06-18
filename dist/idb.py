#!/usr/bin/env python3
"""Parse IRIX `.idb` (Image DataBase) files.

Every IRIX installable package ships an `.idb` file alongside its `.sw`
archives. The .idb is ASCII text listing every file in the package with:
    - install path  (where it lands on the system)
    - archive path  (where it lives inside the .sw bundle)
    - subsystem     (e.g. `4Dwm.sw.4Dwm`)
    - size / sum / offset / cmpsize  (for archive extraction)
    - flags         (modifiers like `needrqs`)

Line format (whitespace-separated, ~9–20 tokens):

    f 0755 root sys usr/bin/X11/4Dwm apps/4Dwm/4Dwm 4Dwm.sw.4Dwm sum(46224) size(686320) off(13) needrqs cmpsize(433917)

First token is the file type:
    f   regular file
    d   directory
    l   symlink (target appears in archive_path)
    b/c block/char device
    h   hardlink (target appears later)
    n   "no-extract" — directory shells already existing on the system

This parser surfaces only what we need to audit + extract: install path,
subsystem, size, archive position. Unknown flag tokens are preserved
verbatim in `.flags` so we don't lose info we don't yet understand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Capture `name(value)` flags — sum, size, off, cmpsize, etc.
_KV_RE = re.compile(r"^([a-z_]+)\(([^)]*)\)$")


@dataclass
class IDBEntry:
    """One file/dir/symlink line from an .idb."""
    type: str                      # f, d, l, b, c, h, n
    mode: int                      # octal mode, e.g. 0o755
    owner: str
    group: str
    install_path: str              # absolute target path (we add leading '/')
    archive_path: str = ""         # path inside the .sw bundle
    subsystem: str = ""            # e.g. "4Dwm.sw.4Dwm"
    size: int = 0                  # uncompressed file size in bytes
    sum: int = 0                   # IRIX checksum (uint32)
    offset: int = 0                # byte offset within the .sw archive
    cmpsize: int = 0               # compressed-size in archive (0 = no compression)
    target: str = ""               # symlink/hardlink target (when type=l/h)
    flags: list[str] = field(default_factory=list)   # any unparsed flag tokens

    @property
    def is_file(self) -> bool:
        return self.type == "f"

    @property
    def is_dir(self) -> bool:
        return self.type == "d"

    @property
    def is_symlink(self) -> bool:
        return self.type == "l"


@dataclass
class IDB:
    """Parsed .idb manifest for one product (a top-level package like 4Dwm)."""
    product: str                   # base name (4Dwm, desktop_eoe, ...)
    path: str = ""                 # source .idb path
    entries: list[IDBEntry] = field(default_factory=list)

    def files(self) -> list[IDBEntry]:
        return [e for e in self.entries if e.is_file]

    def by_subsystem(self) -> dict[str, list[IDBEntry]]:
        out: dict[str, list[IDBEntry]] = {}
        for e in self.entries:
            out.setdefault(e.subsystem, []).append(e)
        return out

    def total_size(self) -> int:
        return sum(e.size for e in self.entries if e.is_file)


# ── Parsing ────────────────────────────────────────────────────────────


def _parse_mode(s: str) -> int:
    try:
        return int(s, 8)
    except ValueError:
        return 0


# Subsystem matches `product.bundle.subname` — e.g. 4Dwm.sw.4Dwm,
# desktop_eoe.man.relnotes, sysadmdesktop.sw.base.
# Product names CAN start with a digit (4Dwm, 3Dgames), so the first
# char is `[a-zA-Z0-9_]`, not `[a-zA-Z_]`.
_SUBSYS_RE = re.compile(
    r"^[a-zA-Z0-9_][\w+]*(?:\.[\w+]+){2,}$"
)


def parse_line(line: str) -> IDBEntry | None:
    """Parse one .idb line. Returns None for blanks/comments/non-file entries.

    The .idb format has two coexisting variants. In some files the
    subsystem appears immediately after archive_path; in others it comes
    at the very end after all kv flags. We handle both by classifying
    every token after install_path as either kv-flag or plain, then
    picking the subsystem out of the plain tokens by name pattern.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    tokens = s.split()
    if not tokens:
        return None
    ftype = tokens[0]
    # Skip non-file directives like exitop(...), preop(...), requires...
    if ftype not in ("f", "d", "l", "b", "c", "h", "n", "p", "s"):
        return None
    if len(tokens) < 5:
        return None

    entry = IDBEntry(
        type=ftype,
        mode=_parse_mode(tokens[1]),
        owner=tokens[2],
        group=tokens[3],
        install_path="/" + tokens[4].lstrip("/"),
    )

    # Walk tokens 5..end. Split into:
    #   - kv flags: match `name(value)`
    #   - plain tokens: everything else (archive_path, subsystem)
    plain: list[str] = []
    flags: list[str] = []
    for tok in tokens[5:]:
        if _KV_RE.match(tok):
            flags.append(tok)
        else:
            plain.append(tok)

    # Plain tokens: identify subsystem by name pattern, treat the rest
    # as positional (archive_path is the first non-subsystem plain).
    subsystem_idx = None
    for i, tok in enumerate(plain):
        if _SUBSYS_RE.match(tok):
            subsystem_idx = i
            entry.subsystem = tok
            break
    positional = [t for i, t in enumerate(plain) if i != subsystem_idx]
    if positional:
        entry.archive_path = positional[0]

    # Decode kv flags into structured fields; preserve unknowns in .flags.
    other_flags: list[str] = []
    for tok in flags:
        m = _KV_RE.match(tok)
        if not m:
            other_flags.append(tok)
            continue
        k, v = m.group(1), m.group(2)
        if k == "size":
            try: entry.size = int(v)
            except ValueError: pass
        elif k == "sum":
            try: entry.sum = int(v)
            except ValueError: pass
        elif k == "off":
            try: entry.offset = int(v)
            except ValueError: pass
        elif k == "cmpsize":
            try: entry.cmpsize = int(v)
            except ValueError: pass
        elif k == "symval":
            entry.target = v
        else:
            # Unrecognized — keep verbatim. Common ones: config(noupdate),
            # link(name), preserve(...), needrqs (rare).
            other_flags.append(tok)
    entry.flags = other_flags
    return entry


def parse_idb(idb_path: str | Path) -> IDB:
    """Parse a .idb file from disk."""
    path = Path(idb_path)
    product = path.stem  # e.g. "4Dwm" from "4Dwm.idb"
    idb = IDB(product=product, path=str(path))
    with open(path, "r", encoding="latin-1") as f:
        for line in f:
            e = parse_line(line)
            if e is not None:
                idb.entries.append(e)
    return idb


def parse_idb_bytes(data: bytes, product: str = "") -> IDB:
    """Parse a .idb whose contents came from somewhere other than a file
    on the host (e.g. extracted from a dist image via efs_read_file_data)."""
    idb = IDB(product=product)
    for line in data.decode("latin-1").splitlines():
        e = parse_line(line)
        if e is not None:
            idb.entries.append(e)
    return idb


# ── CLI ─────────────────────────────────────────────────────────────────


def _main(argv: list[str] | None = None) -> int:
    import argparse, json, sys
    ap = argparse.ArgumentParser(description="Parse an IRIX .idb file.")
    ap.add_argument("idb", help=".idb file path")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--subsystem", help="filter to one subsystem")
    ap.add_argument("--files-only", action="store_true",
                    help="only list regular-file entries")
    args = ap.parse_args(argv)

    idb = parse_idb(args.idb)
    entries = idb.entries
    if args.subsystem:
        entries = [e for e in entries if e.subsystem == args.subsystem]
    if args.files_only:
        entries = [e for e in entries if e.is_file]

    if args.json:
        out = {
            "product": idb.product,
            "path": idb.path,
            "total_files": sum(1 for e in idb.entries if e.is_file),
            "total_bytes": idb.total_size(),
            "subsystems": sorted(idb.by_subsystem().keys()),
            "entries": [
                {
                    "type": e.type, "mode": oct(e.mode), "owner": e.owner,
                    "group": e.group, "install_path": e.install_path,
                    "archive_path": e.archive_path, "subsystem": e.subsystem,
                    "size": e.size, "sum": e.sum, "offset": e.offset,
                    "cmpsize": e.cmpsize, "target": e.target, "flags": e.flags,
                }
                for e in entries
            ],
        }
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"# {idb.product}: {len(idb.entries)} entries, "
              f"{idb.total_size():,} bytes")
        subs = idb.by_subsystem()
        print(f"# subsystems ({len(subs)}): {', '.join(sorted(subs))}")
        print()
        for e in entries:
            print(f"{e.type} {oct(e.mode):>6} {e.owner:8} {e.group:8} "
                  f"{e.size:>10}  {e.install_path}  [{e.subsystem}]")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
