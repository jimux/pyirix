#!/usr/bin/env python3
"""Patch the motif_eoe spec file from IRIX 6.5 Foundation 1.

The motif_eoe.sw64.uil subsystem record has a malformed incompat section:
its nincompat field claims 9 entries but only ~180 bytes remain in the
4149-byte file — far too few for 9 × (3 strings + 2 ints).  The record
is otherwise complete (name, id, prereqs all parse correctly), so the
minimum fix is to zero the 10 bytes covering:

  trailing_skip (2) + nincompat (2) + incompat_skip (2)
  + numstr (2) + nupdates (2)

This makes the record end cleanly with no incompat or update entries for
the sw64.uil subsystem.  All other subsystems are unaffected.

Usage:
    python3 -m pyirix.dist.patch <path-to-motif_eoe>
    python3 -m pyirix.dist.patch --search <foundation-1-dir>
    python3 -m pyirix.dist.patch --verify <path-to-motif_eoe>
"""

import argparse
import struct
import sys
from pathlib import Path

# Expected values that identify the correct file before patching.
EXPECTED_MAGIC     = b'pd001'
EXPECTED_PRODUCT   = 'motif_eoe'
EXPECTED_PKG_TS    = 893936901   # 1998-04-30 — Foundation 1 packaging timestamp
EXPECTED_FILE_SIZE = 4149

# Number of bytes to zero at the patch site.
PATCH_LEN = 10   # trailing_skip + nincompat + incompat_skip + numstr + nupdates


# ── Spec reader (minimal, mirrors parse_spec internals) ────────────────────────
# TODO(pyirix): The _R cursor-reader pattern is independently implemented in
# dist/parser.py (_SpecReader) and dist/pkg_analyzer.py (SpecFileParser).
# Consolidate into a shared utility when the interfaces converge.

class _R:
    """Minimal cursor reader: big-endian shorts, ints, length-prefixed strings."""
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def rs(self) -> int:
        v = struct.unpack_from('>H', self.d, self.p)[0]
        self.p += 2
        return v

    def ri(self) -> int:
        v = struct.unpack_from('>I', self.d, self.p)[0]
        self.p += 4
        return v

    def rb(self) -> int:
        v = self.d[self.p]
        self.p += 1
        return v

    def skip(self, n: int):
        self.p += n

    def rstr(self) -> str:
        n = self.rs()
        s = self.d[self.p:self.p + n].decode('latin-1', errors='replace')
        self.p += n
        return s

    def parse_entries(self, count: int):
        """Skip `count` × (3 strings + 2 ints)."""
        for _ in range(count):
            self.rstr(); self.rstr(); self.rstr()
            self.ri(); self.ri()


# ── Core logic ─────────────────────────────────────────────────────────────────

def find_patch_offset(data: bytes) -> int:
    """Navigate the spec structure to find the byte offset of the malformed
    trailing_skip/nincompat field for motif_eoe.sw64.uil.

    Returns the offset where zeroing starts, or raises ValueError on any
    unexpected structure.
    """
    if data[:5] != EXPECTED_MAGIC:
        raise ValueError("Not a pd001 spec file")

    r = _R(data)
    r.skip(20)                    # fixed header
    spec_type = r.rb()

    product_name = r.rstr()
    if product_name != EXPECTED_PRODUCT:
        raise ValueError(f"Expected product 'motif_eoe', got {product_name!r}")

    r.rstr()                      # product id / description
    r.rb(); r.rb()                # padding
    pkg_ts = r.ri()               # packaging timestamp
    r.rs()                        # skip short
    image_count = r.rs()

    if image_count == 0:
        j = r.rs()
        for _ in range(j):
            r.rstr()
        image_count = r.rs()

    # Walk all images to find image_name == 'sw64'
    for img_idx in range(image_count):
        k = r.rs()
        if k == 0:
            k = r.rs()
        image_name = r.rstr()
        r.rstr()                  # image_id
        r.rs(); r.rs()            # counter, order
        r.ri(); r.ri()            # ver1, ver2
        sc = r.ri()
        if sc == 0:
            sc = r.ri()

        for sub_idx in range(sc):
            pos_sub_start = r.p
            m = r.rs()
            if m == 0:
                m = r.rs()
            sub_name = r.rstr()
            r.rstr()              # subsys id
            r.rstr()              # unknown string
            r.ri()                # unknown int

            nr = r.rs()
            r.parse_entries(nr)
            r.rs()                # skip after replace

            np_ = r.rs()
            r.parse_entries(np_)

            # This is the position of trailing_skip (which we zero along
            # with nincompat, incompat_skip, numstr, nupdates).
            patch_offset = r.p

            if np_ > 0:
                r.rs()            # trailing_skip (consumed normally)

            # Check if this is the target subsystem (sw64.uil with bad nincompat)
            if image_name == 'sw64' and sub_name == 'uil':
                # The patch site is at trailing_skip position.
                return patch_offset

            # Otherwise parse out the type>7 / type>8 blocks normally
            if spec_type > 7:
                ni = r.rs()
                r.parse_entries(ni)
                r.rs()            # skip
                ns = r.rs()
                for _ in range(ns):
                    r.rstr()
            if spec_type > 8:
                nu = r.rs()
                r.parse_entries(nu)

    raise ValueError("Could not locate motif_eoe.sw64.uil subsystem record")


def verify_patch_site(data: bytes, offset: int) -> dict:
    """Read the 10 bytes at `offset` and return a dict describing their
    current interpretation (trailing_skip, nincompat, ...)."""
    if offset + PATCH_LEN > len(data):
        raise ValueError(f"Offset {offset} + {PATCH_LEN} exceeds file length {len(data)}")
    chunk = data[offset:offset + PATCH_LEN]
    fields = struct.unpack_from('>HHHHH', chunk)
    labels = ('trailing_skip', 'nincompat', 'incompat_skip', 'numstr', 'nupdates')
    return dict(zip(labels, fields))


def apply_patch(data: bytearray, offset: int):
    """Zero the 10 bytes at `offset`."""
    data[offset:offset + PATCH_LEN] = b'\x00' * PATCH_LEN


def count_parsed_subsystems(data: bytes) -> int:
    """Count how many subsystems parse_spec extracts from data."""
    from pyirix.dist.parser import parse_spec
    return len(parse_spec(data))


# ── CLI ────────────────────────────────────────────────────────────────────────

def _find_spec_file(search_dir: Path) -> Path:
    """Recursively locate a motif_eoe spec file under search_dir."""
    for p in search_dir.rglob('motif_eoe'):
        if p.is_file() and p.read_bytes()[:5] == EXPECTED_MAGIC:
            return p
    raise FileNotFoundError(
        f"No motif_eoe spec file found under {search_dir}")


def cmd_verify(spec_path: Path):
    data = spec_path.read_bytes()
    print(f"File: {spec_path}  ({len(data)} bytes)")

    # Check file identity
    ok = True
    if data[:5] != EXPECTED_MAGIC:
        print("  FAIL: not a pd001 spec file")
        return 1
    print(f"  magic: pd001 ✓")

    try:
        offset = find_patch_offset(data)
    except ValueError as e:
        print(f"  structure: FAIL — {e}")
        return 1

    fields = verify_patch_site(data, offset)
    print(f"  patch site at offset {offset}:")
    for name, val in fields.items():
        flag = " ← MALFORMED" if name == 'nincompat' and val == 9 else ""
        flag = " ← already zeroed" if val == 0 and not flag else flag
        print(f"    {name:18s} = {val}{flag}")

    all_zero = all(v == 0 for v in fields.values())
    if all_zero:
        print("  status: already patched ✓")
    else:
        print("  status: needs patch")

    n = count_parsed_subsystems(data)
    print(f"  subsystems parsed: {n}")
    return 0


def cmd_patch(spec_path: Path, dry_run: bool = False):
    data = bytearray(spec_path.read_bytes())
    print(f"File: {spec_path}  ({len(data)} bytes)")

    try:
        offset = find_patch_offset(bytes(data))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    fields = verify_patch_site(bytes(data), offset)
    all_zero = all(v == 0 for v in fields.values())

    if all_zero:
        print("Already patched — nothing to do.")
        return 0

    print(f"Patch site at offset {offset}:")
    for name, val in fields.items():
        print(f"  {name:18s}: {val} → 0")

    n_before = count_parsed_subsystems(bytes(data))

    if dry_run:
        print("Dry-run: no changes written.")
        return 0

    apply_patch(data, offset)
    n_after = count_parsed_subsystems(bytes(data))

    spec_path.write_bytes(data)
    print(f"Patched {spec_path}")
    print(f"Subsystems parsed: {n_before} → {n_after}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('spec', nargs='?',
                        help="Path to motif_eoe spec file")
    parser.add_argument('--search', metavar='DIR',
                        help="Search DIR recursively for motif_eoe spec file")
    parser.add_argument('--verify', action='store_true',
                        help="Verify patch state without modifying")
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help="Show what would be patched, don't write")
    args = parser.parse_args()

    if args.search:
        try:
            spec_path = _find_spec_file(Path(args.search))
            print(f"Found: {spec_path}")
        except FileNotFoundError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    elif args.spec:
        spec_path = Path(args.spec)
    else:
        parser.error("Provide a spec file path or --search DIR")
        return 1

    if not spec_path.exists():
        print(f"ERROR: {spec_path} does not exist", file=sys.stderr)
        return 1

    if args.verify:
        return cmd_verify(spec_path)
    else:
        return cmd_patch(spec_path, dry_run=args.dry_run)


if __name__ == '__main__':
    sys.exit(main() or 0)
