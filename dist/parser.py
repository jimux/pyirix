#!/usr/bin/env python3
"""IRIX dist corpus parser library.

Reads IRIX dist directories and tardist files, extracts full dependency
metadata including V630 binary prereq tables, and predicts inst conflicts
for a target hardware configuration before installation.

The key feature over irix_pkg_analyzer.py's InstSimulator is that this library
parses the V630 binary prereq table format, which encodes version-range
constraints (min_ver/max_ver) that cause most real-world install conflicts.

Usage:
    python3 -m pyirix.dist.parser [--target indy]
                                       [--dist DIR ...]
                                       [--tardist FILE|DIR ...]
"""

import argparse
import re
import struct
import sys
import tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Import from pyirix submodules
from pyirix.dist.analyzer import parse_idb_subsystems
from pyirix.dist.pkg_analyzer import (
    DepExprParser, TARGET_CONFIGS, TargetConfig,
    parse_idb_hardware,
)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Prereq:
    """A binary prereq record from a V630/V650 spec file."""
    product: str      # "dmedia_eoe"
    sub_type: str     # "sw"
    sub_name: str     # "base"
    min_ver: int      # 0 = no minimum
    max_ver: int      # 0x7fffffff = no maximum

    @property
    def subsystem_name(self) -> str:
        return f"{self.product}.{self.sub_type}.{self.sub_name}"

    def version_satisfied(self, installed_ver: int) -> bool:
        return self.min_ver <= installed_ver <= self.max_ver


@dataclass
class Subsystem:
    """A subsystem within an IRIX product."""
    name: str           # "cosmoplayer.sw.cosmoplayer"
    product: str        # "cosmoplayer"
    sub_type: str       # "sw"
    sub_name: str       # "cosmoplayer"
    version: int        # ver1 from image record (opaque version comparator)
    file_count: int
    install_size: int
    prereqs: list       # list[Prereq]
    hw_expr: str        # raw text dep expression for hw tests
    dist_source: str    # path of the dist dir/file it came from


@dataclass
class Conflict:
    """A conflict detected during corpus analysis."""
    subsystem: str    # the subsystem with the problem
    kind: str         # "hw_excluded" | "hw_restricted" | "missing_prereq" | "version_range"
    detail: str       # human-readable explanation
    prereq: object    # the Prereq that failed (or None)


@dataclass
class HardwareConfig:
    """Hardware configuration for a target SGI system."""
    cpuboard: str    # "IP22"
    gfxboard: str    # "NEWPORT"
    mode: str        # "32bit"
    cpuarch: str     # "R4000"
    subgr: str       # "NG1"

    @classmethod
    def indy(cls) -> "HardwareConfig":
        return cls.for_target("indy")

    @classmethod
    def indigo2(cls) -> "HardwareConfig":
        return cls.for_target("indigo2")

    @classmethod
    def o2(cls) -> "HardwareConfig":
        return cls.for_target("o2")

    @classmethod
    def for_target(cls, name: str) -> "HardwareConfig":
        if name not in TARGET_CONFIGS:
            raise ValueError(
                f"Unknown target {name!r}. Known: {', '.join(sorted(TARGET_CONFIGS))}")
        tc = TARGET_CONFIGS[name]
        return cls(cpuboard=tc.cpuboard, gfxboard=tc.gfxboard,
                   mode=tc.mode, cpuarch=tc.cpuarch, subgr=tc.subgr)

    def as_target_config(self) -> TargetConfig:
        return TargetConfig(
            cpuboard=self.cpuboard, mode=self.mode, cpuarch=self.cpuarch,
            gfxboard=self.gfxboard, subgr=self.subgr,
        )


@dataclass
class SubsystemConflictReport:
    """Result of a corpus conflict analysis."""
    conflicts: list     # list[Conflict]
    keep_set: set       # set[str] — subsystem names to `keep` before `go`

    def summary(self) -> str:
        by_kind = defaultdict(int)
        for c in self.conflicts:
            by_kind[c.kind] += 1
        lines = [f"Conflicts: {len(self.conflicts)} total"]
        for kind, count in sorted(by_kind.items()):
            lines.append(f"  {kind}: {count}")
        lines.append(f"Keep set: {len(self.keep_set)} subsystems")
        return "\n".join(lines)

    def by_kind(self, kind: str) -> list:
        return [c for c in self.conflicts if c.kind == kind]


# ── Internal constants ────────────────────────────────────────────────────────

# Extensions that are NOT spec files (same set as CDScanner._SKIP_EXT)
_SKIP_EXT = frozenset({
    '.idb', '.sw', '.sw32', '.sw64', '.man', '.books',
    '.data', '.src', '.hdr', '.relnotes', '.help',
    '.redirect', '.iscd', '.tardist',
})

# Subsystem name: product.type.component  (e.g. "eoe.sw.base", "c++_eoe.sw.lib")
# The product name may contain '+' (e.g. "c++_eoe").
_SUBSYS_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_+]*\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*$')

# Text dep expression keywords that flag a hw-restriction expression
_DEP_KEYWORDS = (b'&&', b'||', b'noship', b'CPUBOARD', b'DMODE',
                 b'GFXBOARD', b'MODE=', b'SUBGR', b'CPUARCH')


# ── Cursor-based binary reader (mirrors specfile.c field-by-field) ─────────────
# TODO(pyirix): The _SpecReader pattern is independently implemented in
# dist/pkg_analyzer.py (SpecFileParser) and dist/patch.py (_R class).
# Consolidate into a shared utility when the interfaces converge.

class _SpecReader:
    """Cursor-based reader that follows specfile.c's getstring/getshort/getlong."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError("EOF reading byte")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_short(self) -> int:
        """Read 2-byte big-endian unsigned short (getshort in specfile.c)."""
        if self.pos + 2 > len(self.data):
            raise EOFError("EOF reading short")
        val = struct.unpack_from('>H', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_int(self) -> int:
        """Read 4-byte big-endian unsigned int (getlong in specfile.c)."""
        if self.pos + 4 > len(self.data):
            raise EOFError("EOF reading int")
        val = struct.unpack_from('>I', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_str(self) -> str:
        """Read 2-byte BE length-prefixed string (getstring in specfile.c)."""
        length = self.read_short()
        if self.pos + length > len(self.data):
            raise EOFError(f"EOF reading string of length {length}")
        raw = self.data[self.pos:self.pos + length]
        self.pos += length
        return raw.decode('latin-1', errors='replace')

    def skip(self, n: int):
        if self.pos + n > len(self.data):
            raise EOFError(f"EOF skipping {n} bytes")
        self.pos += n


def _parse_entry_list(rdr: _SpecReader, count: int) -> list:
    """Parse `count` entries of (3 strings + 2 ints) — printsubsys() in specfile.c.

    Each entry encodes one side of a prereq/replace/incompat/updates relationship:
      string 1 → product component (e.g. "eoe")
      string 2 → image/type component (e.g. "sw")
      string 3 → subsystem component (e.g. "base")
      int 1    → min_ver
      int 2    → max_ver
    """
    entries = []
    for _ in range(count):
        s1 = rdr.read_str()
        s2 = rdr.read_str()
        s3 = rdr.read_str()
        min_ver = rdr.read_int()
        max_ver = rdr.read_int()
        entries.append((s1, s2, s3, min_ver, max_ver))
    return entries


# ── Core parser function ──────────────────────────────────────────────────────

def parse_spec(data: bytes, source: str = "") -> list:
    """Parse a pd001 spec file following specfile.c field order exactly.

    Returns one Subsystem per subsystem record found.
    Returns [] if data is not a valid spec file or parsing fails.

    Field layout (specfile.c reference):
      [20 bytes]  header ("pd001V630P00" + magic)
      [1 byte]    type   (controls optional sections)
      [str]       product name  (2-byte BE length prefix)
      [str]       product id    (2-byte BE length prefix)
      [2 bytes]   padding (2 × fgetc)
      [4 bytes]   packaging_ts  (BE int, Unix timestamp of build)
      [2 bytes]   skip
      [2 bytes]   image_count   (if 0: read j shorts-worth of extra strings, re-read count)

      Per image:
        [2 bytes]   k flags   (if 0, read another short — eoe_6528m edge case)
        [str]       image name
        [str]       image id   ("P<pkg_ts>_<something>")
        [2 bytes]   counter
        [2 bytes]   order
        [4 bytes]   ver1  — opaque version comparator used by inst
        [4 bytes]   ver2
        [4 bytes]   subsys_count  (if 0, read another int)

        Per subsystem:
          [2 bytes]   m flags   (if 0, read another short)
          [str]       subsys name  (e.g. "eoe.sw.base")
          [str]       subsys id
          [str]       unknown str  (may be hw dep expression)
          [4 bytes]   unknown int
          [2 bytes]   nreplace → nreplace × (3 strings + 2 ints)
          [2 bytes]   skip  (after replace block)
          [2 bytes]   nprereq → nprereq × (3 strings + 2 ints)
          [2 bytes]   trailing skip  (only if nprereq > 0)
          if type > 7:
            [2 bytes] nincompat → nincompat × (3 strings + 2 ints)
            [2 bytes] skip
            [2 bytes] numstr → numstr strings
          if type > 8:
            [2 bytes] nupdates → nupdates × (3 strings + 2 ints)
    """
    if len(data) < 21 or data[:5] != b'pd001':
        return []

    rdr = _SpecReader(data)
    try:
        # Skip the fixed 20-byte header
        rdr.skip(20)

        # Type byte — controls which optional blocks are present
        spec_type = rdr.read_byte()

        # Product name and id (description string)
        product_name = rdr.read_str()
        _description = rdr.read_str()

        if not product_name:
            return []

        # 2 padding bytes (fgetc × 2 in specfile.c)
        rdr.read_byte()
        rdr.read_byte()

        # Packaging timestamp — real Unix timestamp from build era (e.g. 1999)
        _packaging_ts = rdr.read_int()

        # Skip short (discarded)
        rdr.read_short()

        # Image count
        image_count = rdr.read_short()

        # Edge case: image_count == 0 → read extra strings then re-read count
        # (confirmed on cosmoplayer: count=0, j=1, real count=4)
        if image_count == 0:
            j = rdr.read_short()
            for _ in range(j):
                rdr.read_str()
            image_count = rdr.read_short()

        subsystems = []

        for _img_idx in range(image_count):
            # k flags — if 0, read another short (eoe_6528m edge case)
            k = rdr.read_short()
            if k == 0:
                k = rdr.read_short()

            # Image name and id
            image_name = rdr.read_str()   # e.g. "sw", "man", "lang"
            _image_id = rdr.read_str()    # "P<pkg_ts>_<something>"

            # Counter and order (printed but not semantically used)
            rdr.read_short()  # counter
            rdr.read_short()  # order

            # Version integers — ver1 is the opaque version comparator used by
            # inst for prereq range checking. Higher = newer. Not a timestamp.
            ver1 = rdr.read_int()
            _ver2 = rdr.read_int()

            # Subsystem count — if 0, read another int
            subsys_count = rdr.read_int()
            if subsys_count == 0:
                subsys_count = rdr.read_int()

            for _sub_idx in range(subsys_count):
                # m flags — if 0, read another short (same edge case as k)
                m = rdr.read_short()
                if m == 0:
                    m = rdr.read_short()

                # Subsystem SHORT name (e.g. "base", "4Dwm", "cn").
                # The full dotted name is: product_name + "." + image_name + "." + short_name
                subsys_short = rdr.read_str()
                subsys_name = f"{product_name}.{image_name}.{subsys_short}"

                # Subsystem id and unknown string (third string may be hw_expr)
                _subsys_id = rdr.read_str()
                unknown_str = rdr.read_str()

                # Unknown int (discarded)
                rdr.read_int()

                # Replace entries — MUST be parsed before reading the skip short
                nreplace = rdr.read_short()
                _replace_entries = _parse_entry_list(rdr, nreplace)
                # Skip short comes AFTER parsing replace entries
                rdr.read_short()

                # Prereq entries
                nprereq = rdr.read_short()
                prereq_entries = _parse_entry_list(rdr, nprereq)
                # Trailing skip only when nprereq > 0
                if nprereq > 0:
                    rdr.read_short()

                # type > 7: incompat block + numstr extra strings
                if spec_type > 7:
                    nincompat = rdr.read_short()
                    _incompat_entries = _parse_entry_list(rdr, nincompat)
                    rdr.read_short()  # skip
                    numstr = rdr.read_short()
                    for _ in range(numstr):
                        rdr.read_str()

                # type > 8: updates block
                if spec_type > 8:
                    nupdates = rdr.read_short()
                    _parse_entry_list(rdr, nupdates)

                # Build Prereq objects from parsed entries
                prereqs = []
                for s1, s2, s3, min_ver, max_ver in prereq_entries:
                    if s1 and s2 and s3:
                        prereqs.append(Prereq(
                            product=s1,
                            sub_type=s2,
                            sub_name=s3,
                            min_ver=min_ver,
                            max_ver=max_ver,
                        ))

                # hw_expr: check unknown_str for hardware dependency keywords
                hw_expr = ""
                unknown_bytes = unknown_str.encode('latin-1', errors='replace')
                if any(kw in unknown_bytes for kw in _DEP_KEYWORDS):
                    hw_expr = unknown_str.strip()

                # Parse subsystem name into product/type/component parts
                parts = subsys_name.split('.')
                if len(parts) >= 3:
                    sub_product, sub_type_str, sub_name_part = parts[0], parts[1], parts[2]
                elif len(parts) == 2:
                    sub_product, sub_type_str, sub_name_part = parts[0], parts[1], parts[1]
                else:
                    sub_product = subsys_name
                    sub_type_str = 'sw'
                    sub_name_part = subsys_name

                subsystems.append(Subsystem(
                    name=subsys_name,
                    product=sub_product,
                    sub_type=sub_type_str,
                    sub_name=sub_name_part,
                    version=ver1,
                    file_count=0,
                    install_size=0,
                    prereqs=prereqs,
                    hw_expr=hw_expr,
                    dist_source=source,
                ))

        return subsystems

    except (EOFError, struct.error):
        # Return whatever subsystems were successfully parsed before the error.
        # Some spec files (e.g. motif_eoe Foundation 1) have malformed records
        # in the last subsystem; partial results are better than nothing.
        return subsystems


def _parse_idb_text(idb_text: str) -> dict:
    """Parse IDB text in memory.

    Returns {subsystem_name: (file_count, total_size)}.
    Handles both column-6 and end-of-line subsystem name positions.
    """
    subsystems: dict = defaultdict(lambda: {"files": 0, "total_size": 0})
    size_re = re.compile(r'(?<![a-z])size\((\d+)\)')

    for line in idb_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        if parts[0] not in ('d', 'f', 'l', 'c', 'b', 'p'):
            continue

        # Try column 6 first, then scan remaining fields
        if _SUBSYS_RE.match(parts[6]):
            package = parts[6]
            rest = ' '.join(parts[7:])
        else:
            package = None
            rest_start = 7
            for k in range(7, len(parts)):
                if _SUBSYS_RE.match(parts[k]):
                    package = parts[k]
                    rest_start = k + 1
                    break
            if package is None:
                continue
            rest = ' '.join(parts[rest_start:])

        subsystems[package]["files"] += 1
        m = size_re.search(rest)
        if m:
            subsystems[package]["total_size"] += int(m.group(1))

    return {k: (v["files"], v["total_size"]) for k, v in subsystems.items()}


def parse_idb(path) -> dict:
    """Parse an IDB file from disk.

    Returns {subsystem_name: (file_count, total_size)}.
    """
    try:
        raw = parse_idb_subsystems(Path(path))
        return {k: (v['files'], v['total_size']) for k, v in raw.items()}
    except Exception:
        return {}


# ── Corpus class ──────────────────────────────────────────────────────────────

class Corpus:
    """An indexed collection of IRIX packages from any source.

    Loads spec + IDB files from dist directories or tardist archives,
    deduplicates by subsystem name (newest version wins), and provides
    conflict analysis against a target HardwareConfig.
    """

    def __init__(self):
        self._subsystems: dict = {}    # name -> Subsystem (newest version wins)
        self._idb_texts: dict = {}     # idb_key -> idb_text_string (for hw analysis)

    # ── Loaders ───────────────────────────────────────────────────────────────

    def load_dir(self, dist_dir: Path) -> int:
        """Load all products from one dist directory.

        Two-pass approach:
          Pass 1: Parse spec files (pd001 magic) to collect per-subsystem
                  prerequisites, hw_expr, and version.  Also build a
                  stem→version map for products that lack spec entries.
          Pass 2: Scan all .idb files to discover EVERY subsystem — including
                  those with no prerequisites and therefore absent from the
                  spec file (e.g. eoe.sw.base, eoe.sw.unix, eoe.sw.gfx).

        Returns subsystem count added/updated.
        """
        dist_dir = Path(dist_dir)
        if not dist_dir.exists():
            return 0

        count = 0
        source = str(dist_dir)

        # ── Pass 1: spec files ────────────────────────────────────────────
        # Map: spec_stem -> version (ver1 from spec), subsys_name -> Subsystem
        spec_by_stem: dict = {}   # stem -> version (ver1)
        spec_subs: dict = {}      # subsys_name -> Subsystem

        for entry in sorted(dist_dir.iterdir()):
            if not entry.is_file() or entry.suffix.lower() in _SKIP_EXT:
                continue
            try:
                header = entry.read_bytes()[:5]
            except OSError:
                continue
            if header != b'pd001':
                continue
            try:
                data = entry.read_bytes()
            except OSError:
                continue

            stem = entry.name  # no extension for spec files
            subs = parse_spec(data, source=source)
            if subs:
                # All subsystems in a spec share the same ver1; use the first
                spec_by_stem[stem] = subs[0].version
            for sub in subs:
                spec_subs[sub.name] = sub

        # ── Pass 2: IDB files ─────────────────────────────────────────────
        # Every subsystem in the IDB goes into the corpus.  For subsystems
        # already found in the spec file we use their spec entry (which has
        # prereqs and version).  For IDB-only subsystems we synthesise an
        # entry using the version from the companion spec file.

        for entry in sorted(dist_dir.iterdir()):
            if not entry.is_file() or entry.suffix.lower() != '.idb':
                continue

            stem = entry.stem   # "eoe" from "eoe.idb"
            ver_for_product = spec_by_stem.get(stem, 0)

            try:
                idb_text = entry.read_text(encoding='latin-1', errors='replace')
            except OSError:
                continue

            self._idb_texts[str(entry)] = idb_text
            idb_counts = _parse_idb_text(idb_text)

            for sub_name, (fc, isz) in idb_counts.items():
                if sub_name in spec_subs:
                    sub = spec_subs[sub_name]
                    sub.file_count = fc
                    sub.install_size = isz
                else:
                    parts = sub_name.split('.')
                    sub = Subsystem(
                        name=sub_name,
                        product=parts[0],
                        sub_type=parts[1] if len(parts) > 1 else 'sw',
                        sub_name=parts[2] if len(parts) > 2 else (parts[-1] if parts else sub_name),
                        version=ver_for_product,
                        file_count=fc,
                        install_size=isz,
                        prereqs=[],
                        hw_expr='',
                        dist_source=source,
                    )

                existing = self._subsystems.get(sub_name)
                if existing is None or sub.version > existing.version:
                    self._subsystems[sub_name] = sub
                    count += 1

        return count

    def load_dirs(self, dist_dirs: list) -> int:
        """Load from multiple dist directories.  Returns total count added."""
        total = 0
        for d in dist_dirs:
            total += self.load_dir(Path(d))
        return total

    def load_tardist(self, tardist_path: Path) -> int:
        """Load all products from one tardist (.tardist) file.

        Reads the ustar tar archive in memory, extracts spec + .idb members
        (handling both relative and /usr/dist/ path conventions).  Uses the
        same two-pass approach as load_dir(): spec files for prereqs/version,
        IDB files for the full subsystem list.
        Returns subsystem count added/updated.
        """
        tardist_path = Path(tardist_path)
        if not tardist_path.exists():
            return 0

        count = 0
        source = str(tardist_path)

        try:
            with tarfile.open(str(tardist_path), 'r:') as tf:
                spec_bytes: dict = {}  # stem -> bytes
                idb_bytes: dict = {}   # stem -> bytes

                for member in tf.getmembers():
                    if not member.isfile():
                        continue

                    name = member.name
                    # Normalise: strip /usr/dist/ prefix and leading /
                    if name.startswith('/usr/dist/'):
                        name = name[len('/usr/dist/'):]
                    elif name.startswith('/'):
                        name = name.lstrip('/')

                    basename = Path(name).name
                    suffix = Path(basename).suffix.lower()

                    # Skip payload members — only need spec and .idb
                    if suffix in (_SKIP_EXT - {'.idb'}):
                        continue

                    try:
                        fobj = tf.extractfile(member)
                        if fobj is None:
                            continue
                        content = fobj.read()
                    except Exception:
                        continue

                    if suffix == '.idb':
                        stem = Path(basename).stem
                        idb_bytes[stem] = content
                    elif content[:5] == b'pd001':
                        # Spec file (no meaningful extension)
                        stem = Path(basename).stem if suffix else basename
                        spec_bytes[stem] = content

                # ── Pass 1: build spec_subs and stem→version ──────────────
                spec_by_stem: dict = {}
                spec_subs: dict = {}
                for stem, data in spec_bytes.items():
                    subs = parse_spec(data, source=source)
                    if subs:
                        spec_by_stem[stem] = subs[0].version
                    for sub in subs:
                        spec_subs[sub.name] = sub

                # ── Pass 2: IDB files for complete subsystem list ─────────
                for stem, raw_idb in idb_bytes.items():
                    try:
                        idb_text = raw_idb.decode('latin-1', errors='replace')
                    except Exception:
                        continue

                    idb_key = f"{source}::{stem}"
                    self._idb_texts[idb_key] = idb_text
                    idb_counts = _parse_idb_text(idb_text)
                    ver_for_product = spec_by_stem.get(stem, 0)

                    for sub_name, (fc, isz) in idb_counts.items():
                        if sub_name in spec_subs:
                            sub = spec_subs[sub_name]
                            sub.file_count = fc
                            sub.install_size = isz
                        else:
                            parts = sub_name.split('.')
                            sub = Subsystem(
                                name=sub_name,
                                product=parts[0],
                                sub_type=parts[1] if len(parts) > 1 else 'sw',
                                sub_name=(parts[2] if len(parts) > 2
                                          else (parts[-1] if parts else sub_name)),
                                version=ver_for_product,
                                file_count=fc,
                                install_size=isz,
                                prereqs=[],
                                hw_expr='',
                                dist_source=source,
                            )

                        existing = self._subsystems.get(sub_name)
                        if existing is None or sub.version > existing.version:
                            self._subsystems[sub_name] = sub
                            count += 1

        except (tarfile.TarError, OSError):
            pass

        return count

    def load_tardist_dir(self, directory: Path, glob: str = "*.tardist") -> int:
        """Load all tardist files in a directory.  Returns total count added."""
        directory = Path(directory)
        total = 0
        for tardist in sorted(directory.glob(glob)):
            total += self.load_tardist(tardist)
        return total

    # ── Query ─────────────────────────────────────────────────────────────────

    @property
    def subsystems(self) -> dict:
        """All known subsystems, newest version wins for same name."""
        return dict(self._subsystems)

    def selected_subsystems(self, hw: HardwareConfig) -> set:
        """Returns the subsystem names inst would select for 'install standard'.

        Includes .sw subsystems (always), .sw64 (for 64-bit targets), and
        .sw32 (for 32-bit targets) — mirroring inst's default selection logic.
        """
        selected = set()
        for name in self._subsystems:
            parts = name.split('.')
            if len(parts) < 2:
                continue
            sub_type = parts[1]
            if sub_type == 'sw':
                selected.add(name)
            elif sub_type == 'sw64' and hw.mode == '64bit':
                selected.add(name)
            elif sub_type == 'sw32' and hw.mode == '32bit':
                selected.add(name)
        return selected

    def conflicts(self, hw: HardwareConfig) -> SubsystemConflictReport:
        """Compute all conflicts for the given hardware config.

        For each subsystem in selected_subsystems():
          1. hw_excluded  — IDB hw analysis shows zero target files
          2. hw_restricted — hw_expr text expression fails for this hw
          3. missing_prereq — a binary prereq's subsystem not in corpus
          4. version_range — installed prereq version outside [min_ver, max_ver]

        Returns SubsystemConflictReport with all conflicts + the derived keep_set.
        """
        tc = hw.as_target_config()
        all_sub_names = set(self._subsystems.keys())
        selected = self.selected_subsystems(hw)

        # Build hw-exclusion cache by running parse_idb_hardware on each
        # IDB text we collected during load_dir / load_tardist.
        idb_hw_cache: dict = {}
        seen_ids: set = set()
        for idb_text in self._idb_texts.values():
            tid = id(idb_text)
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            try:
                hw_info = parse_idb_hardware(idb_text, tc)
                idb_hw_cache.update(hw_info)
            except Exception:
                pass

        conflicts_list: list = []

        for sub_name in sorted(selected):
            sub = self._subsystems[sub_name]

            # ── 1. hw_excluded ────────────────────────────────────────────
            hw_info = idb_hw_cache.get(sub_name)
            if hw_info and hw_info.get('fully_excluded', False):
                conflicts_list.append(Conflict(
                    subsystem=sub_name,
                    kind='hw_excluded',
                    detail=(f"{sub_name}: {hw_info['total_files']} files total, "
                            f"0 for {hw.cpuboard}"),
                    prereq=None,
                ))
                continue  # no point checking other conflicts

            # ── 2. hw_restricted ─────────────────────────────────────────
            if sub.hw_expr:
                parser = DepExprParser(all_sub_names, tc)
                if not parser.evaluate(sub.hw_expr):
                    conflicts_list.append(Conflict(
                        subsystem=sub_name,
                        kind='hw_restricted',
                        detail=f"{sub_name} hw restriction: {sub.hw_expr!r}",
                        prereq=None,
                    ))
                    continue

            # ── 3 & 4. Binary prereqs (V630/V650) ────────────────────────
            for prereq in sub.prereqs:
                prereq_sub = prereq.subsystem_name

                if prereq_sub not in all_sub_names:
                    conflicts_list.append(Conflict(
                        subsystem=sub_name,
                        kind='missing_prereq',
                        detail=(f"{sub_name} requires {prereq_sub} "
                                f"[{prereq.min_ver}..{prereq.max_ver}] — not in corpus"),
                        prereq=prereq,
                    ))
                else:
                    installed = self._subsystems[prereq_sub]
                    if not prereq.version_satisfied(installed.version):
                        conflicts_list.append(Conflict(
                            subsystem=sub_name,
                            kind='version_range',
                            detail=(f"{sub_name} requires {prereq_sub} version "
                                    f"[{prereq.min_ver}..{prereq.max_ver}], "
                                    f"have {installed.version}"),
                            prereq=prereq,
                        ))

        keep_set = {c.subsystem for c in conflicts_list}
        return SubsystemConflictReport(conflicts=conflicts_list, keep_set=keep_set)


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IRIX dist corpus parser — pre-compute inst conflict keep_set")
    parser.add_argument("--target", default="indy",
                        choices=sorted(TARGET_CONFIGS),
                        help="Target hardware (default: indy)")
    parser.add_argument("--dist", metavar="DIR", nargs="+", default=[],
                        help="Dist directories to load")
    parser.add_argument("--tardist", metavar="FILE_OR_DIR", nargs="+", default=[],
                        help="Tardist files or directories to load")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all conflicts (not just summary)")
    args = parser.parse_args()

    if not args.dist and not args.tardist:
        parser.error("Provide at least one --dist or --tardist argument")

    corpus = Corpus()

    for d in args.dist:
        p = Path(d)
        if not p.exists():
            print(f"WARNING: dist dir not found: {d}", file=sys.stderr)
            continue
        n = corpus.load_dir(p)
        print(f"  Loaded {n} subsystems from {d}")

    for t in args.tardist:
        p = Path(t)
        if not p.exists():
            print(f"WARNING: tardist path not found: {t}", file=sys.stderr)
            continue
        if p.is_dir():
            n = corpus.load_tardist_dir(p)
            print(f"  Loaded {n} subsystems from tardist dir {t}")
        else:
            n = corpus.load_tardist(p)
            print(f"  Loaded {n} subsystems from tardist {t}")

    print(f"\nCorpus: {len(corpus.subsystems)} subsystems total")

    hw = HardwareConfig.for_target(args.target)
    print(f"Target: {args.target} ({hw.cpuboard}, {hw.mode}, {hw.gfxboard})\n")

    report = corpus.conflicts(hw)
    print(report.summary())

    if args.verbose or report.conflicts:
        print()
        for kind in ('hw_excluded', 'hw_restricted', 'missing_prereq', 'version_range'):
            items = report.by_kind(kind)
            if not items:
                continue
            print(f"── {kind} ({len(items)}) ──")
            for c in items:
                print(f"  {c.detail}")
            print()

    if report.keep_set:
        print("── keep_set (send to inst before go) ──")
        for sub in sorted(report.keep_set):
            print(f"  keep {sub}")


if __name__ == "__main__":
    main()
