#!/usr/bin/env python3
"""Analyze IRIX distribution packages for version conflicts before combining.

Parses spec file binary headers to extract product names, version timestamps,
and format versions. Detects conflicts, family mismatches, and prerequisite
gaps across CD collections. Integrates with combine_dist.py configurations.

Usage:
    python3 -m pyirix.dist.pkg_analyzer analyze [--config 6.5|6.5.5|mipspro]
    python3 -m pyirix.dist.pkg_analyzer analyze --images *.img
    python3 -m pyirix.dist.pkg_analyzer versions [--config 6.5]
    python3 -m pyirix.dist.pkg_analyzer conflicts [--images CD1.img CD2.img]
    python3 -m pyirix.dist.pkg_analyzer search PRODUCT [--min-version TS]
    python3 -m pyirix.dist.pkg_analyzer validate-config 6.5
    python3 -m pyirix.dist.pkg_analyzer scan-image IRIX_6.5_Foundation_1.img
    python3 -m pyirix.dist.pkg_analyzer db [--detail HASH] [--scan-all] [--drop]
    python3 -m pyirix.dist.pkg_analyzer compat image1.img image2.img ...
    python3 -m pyirix.dist.pkg_analyzer simulate --image combined.img --target indy
    python3 -m pyirix.dist.pkg_analyzer simulate --dist /path/to/dist/ --target indy [-v]
"""

import argparse
import hashlib
import os
import re
import sqlite3
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTRACT_BASE = PROJECT_ROOT / "software_library" / "extraced_irix_cds"

# Import functions from pyirix submodules
from pyirix.dist.analyzer import parse_idb_subsystems, extract_deps_from_spec


# ── Data classes ──────────────────────────────────────────────────

@dataclass
class ProductInfo:
    spec_filename: str        # e.g., "eoe_6522m"
    product_name: str         # e.g., "eoe" (canonical, without version suffix)
    description: str          # e.g., "IRIX Execution Environment, 6.5.22"
    v_code: str               # e.g., "V650"
    version_ts: Optional[int] # e.g., 1289434520
    product_id: Optional[str] # e.g., "P1065513425_1289434520"
    cd_source: str            # e.g., "irix-6.5.22-overlay-1"
    subsystem_names: list = field(default_factory=list)
    dep_references: list = field(default_factory=list)


@dataclass
class CDInfo:
    name: str                     # Display name
    path: Path                    # Path to dist directory
    products: list = field(default_factory=list)  # list[ProductInfo]
    version_family: str = ""      # Detected: "6.5-foundation", "6.5.22-overlay"
    median_timestamp: Optional[int] = None


@dataclass
class VersionConflict:
    product_name: str
    entries: list = field(default_factory=list)  # [(cd_name, version_ts, spec_filename)]
    resolution: str = ""  # "overlay_supersedes" | "same_version" | "conflict"


@dataclass
class PrerequisiteGap:
    required_subsystem: str
    required_by: list = field(default_factory=list)
    available_on: Optional[str] = None


@dataclass
class FamilyMismatch:
    cd_name: str
    cd_family: str
    expected_family: str
    severity: str = "warning"
    detail: str = ""


@dataclass
class ConflictReport:
    version_conflicts: list = field(default_factory=list)
    prerequisite_gaps: list = field(default_factory=list)
    family_mismatches: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    safe_to_combine: bool = True

    def print_summary(self):
        """Print a concise summary for integration with combine_dist.py."""
        conflicts = [c for c in self.version_conflicts
                     if c.resolution == "conflict"]
        errors = [m for m in self.family_mismatches if m.severity == "error"]

        if not conflicts and not errors:
            print("  Pre-flight: OK (no version conflicts)")
        else:
            print(f"  Pre-flight: {len(conflicts)} conflict(s), "
                  f"{len(errors)} error(s)")
            for c in conflicts[:3]:
                timestamps = ", ".join(
                    f"{e[0]}={e[1]}" for e in c.entries)
                print(f"    {c.product_name}: {timestamps}")
            for e in errors[:3]:
                print(f"    {e.cd_name}: {e.detail}")
            if not self.safe_to_combine:
                print("  WARNING: conflicts detected -- review before combining")


# ── inst Simulator Data Classes ──────────────────────────────────

@dataclass
class TargetConfig:
    """Hardware configuration for a target SGI system."""
    cpuboard: str    # "IP22"
    mode: str        # "32bit"
    cpuarch: str     # "R4000"
    gfxboard: str    # "NEWPORT"
    subgr: str       # "NG1"


TARGET_CONFIGS = {
    "indy":          TargetConfig("IP22", "32bit", "R4000", "NEWPORT", "NG1"),
    "indy-r5k":     TargetConfig("IP22", "32bit", "R5000", "NEWPORT", "NG1"),
    "indigo2":       TargetConfig("IP22", "32bit", "R4000", "EXPRESS", "EXPRESS"),
    "indigo2-r10k":  TargetConfig("IP28", "64bit", "R10000", "MGRAS", "MGRAS"),
    "o2":            TargetConfig("IP32", "32bit", "R5000", "CRIME", "CRM"),
    "octane":        TargetConfig("IP30", "64bit", "R10000", "MGRAS", "RACER"),
}


@dataclass
class SubsystemRecord:
    """A subsystem within a product, with dependency and hw info."""
    name: str                        # e.g., "eoe.sw.base"
    product: str                     # e.g., "eoe"
    subsys_type: str                 # e.g., "sw"
    total_files: int = 0
    total_size: int = 0
    target_files: int = 0            # Files matching target hw
    target_size: int = 0
    dep_expression: str = ""         # Raw dependency expression
    hw_expression: str = ""          # Hardware restriction from spec
    fully_excluded: bool = False     # True if 0 files match target
    is_default: bool = False         # True if .sw (or .sw64 with 64bit)


@dataclass
class InstConflict:
    """A conflict detected during inst simulation."""
    conflict_type: str  # "missing_prereq", "hw_excluded", "hw_restricted"
    subsystem: str      # Subsystem that has the conflict
    detail: str         # Human-readable description
    resolution: str     # Suggested resolution


@dataclass
class SimulationResult:
    """Result of an inst simulation run."""
    target: TargetConfig
    target_name: str
    total_products: int = 0
    total_subsystems: int = 0
    selected_subsystems: int = 0
    hw_excluded_subsystems: int = 0
    conflicts: list = field(default_factory=list)
    install_size: int = 0            # Estimated install size for target
    subsystem_records: list = field(default_factory=list)


# ── inst Simulator: mach() Expression Evaluator ──────────────────

def _target_get(target, varname):
    """Get a target config value by variable name (case-insensitive)."""
    mapping = {
        'CPUBOARD': target.cpuboard,
        'MODE': target.mode,
        'DMODE': target.mode,
        'CPUARCH': target.cpuarch,
        'GFXBOARD': target.gfxboard,
        'SUBGR': target.subgr,
    }
    return mapping.get(varname.upper())


def eval_mach_expr(mach_str, target):
    """Evaluate an IDB mach() expression against a target config.

    Handles three patterns found in real IDB data:
    1. Space-separated same-var = OR: "CPUBOARD=IP22 CPUBOARD=IP28"
    2. Different vars = AND:          "CPUBOARD=IP30 GFXBOARD=MGRAS"
    3. && with !=:                    "CPUBOARD!=IP27 && CPUBOARD!=IP30"

    Returns True if the target matches the expression.
    """
    mach_str = mach_str.strip()
    if not mach_str:
        return True

    # Pattern 3: explicit && connector (always uses !=)
    if '&&' in mach_str:
        parts = [p.strip() for p in mach_str.split('&&')]
        return all(_eval_single_test(p, target) for p in parts)

    # Patterns 1 & 2: space-separated tokens
    # Group by variable name: same var = OR, different vars = AND
    tokens = mach_str.split()
    var_groups = defaultdict(list)
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if '!=' in token:
            var, val = token.split('!=', 1)
            var = _normalize_varname(var)
            var_groups[var].append(('!=', val))
        elif '=' in token:
            var, val = token.split('=', 1)
            var = _normalize_varname(var)
            var_groups[var].append(('==', val))
        else:
            # Bare name like "IP22" -> CPUBOARD=IP22
            var_groups['CPUBOARD'].append(('==', token))

    # Evaluate: OR within same variable, AND between different variables
    for var, tests in var_groups.items():
        target_val = _target_get(target, var)
        if target_val is None:
            # Unknown variable — treat != as True, == as False
            eq_tests = [v for op, v in tests if op == '==']
            neq_tests = [v for op, v in tests if op == '!=']
            if eq_tests and not neq_tests:
                return False
            continue

        # Check this variable's tests (OR semantics for == tests)
        eq_tests = [(op, v) for op, v in tests if op == '==']
        neq_tests = [(op, v) for op, v in tests if op == '!=']

        if eq_tests:
            # At least one must match
            if not any(target_val == v for _, v in eq_tests):
                return False
        if neq_tests:
            # All must match (AND semantics for !=)
            if not all(target_val != v for _, v in neq_tests):
                return False

    return True


def _normalize_varname(var):
    """Normalize variable names: DMODE -> MODE, etc."""
    var = var.upper().strip()
    if var == 'DMODE':
        return 'MODE'
    return var


def _eval_single_test(token, target):
    """Evaluate a single VAR=VAL or VAR!=VAL test."""
    token = token.strip()
    if '!=' in token:
        var, val = token.split('!=', 1)
        target_val = _target_get(target, var.strip())
        return target_val is None or target_val != val.strip()
    elif '=' in token:
        var, val = token.split('=', 1)
        target_val = _target_get(target, var.strip())
        return target_val is not None and target_val == val.strip()
    else:
        # Bare name — treat as CPUBOARD==name
        target_val = _target_get(target, 'CPUBOARD')
        return target_val == token.strip()


# ── inst Simulator: Dependency Expression Parser ─────────────────

class DepExprParser:
    """Recursive descent parser for spec file dependency expressions.

    Grammar:
        expr     ::= or_expr
        or_expr  ::= and_expr ('||' and_expr)*
        and_expr ::= unary ('&&' unary)*
        unary    ::= '!' unary | '(' expr ')' | atom
        atom     ::= subsystem_ref | var_test | literal

    Atoms:
        subsystem_ref: product.type.subsystem (e.g., "eoe_eoe.sw.base")
        var_test: VAR=VAL or VAR!=VAL (e.g., "DMODE=64bit")
        literal: bare word (e.g., "noship")
    """

    _SUBSYS_RE = re.compile(
        r'^[a-zA-Z_][a-zA-Z0-9_+]*\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*$')
    _VAR_TEST_RE = re.compile(r'^[A-Z][A-Z0-9_]*[!=]+')

    def __init__(self, available_subsystems, target):
        """Initialize with set of available subsystem names and target config."""
        self.available = available_subsystems  # set of subsystem names
        self.target = target
        self.pos = 0
        self.tokens = []

    def evaluate(self, expr_str):
        """Parse and evaluate a dependency expression. Returns True if satisfied."""
        expr_str = expr_str.strip()
        if not expr_str:
            return True
        self.tokens = self._tokenize(expr_str)
        self.pos = 0
        try:
            result = self._parse_or()
            return result
        except (IndexError, ValueError):
            # Parse error — conservatively return True (don't flag as conflict)
            return True

    def _tokenize(self, expr):
        """Split expression into tokens, preserving operators and parens."""
        tokens = []
        i = 0
        while i < len(expr):
            c = expr[i]
            if c in ' \t\n\r':
                i += 1
                continue
            if c == '(' or c == ')':
                tokens.append(c)
                i += 1
            elif c == '!' and i + 1 < len(expr) and expr[i + 1] == '=':
                # Part of != in a var test — accumulate into atom
                # Back up and let atom parsing handle it
                atom, end = self._read_atom(expr, i)
                tokens.append(atom)
                i = end
            elif c == '!':
                tokens.append('!')
                i += 1
            elif expr[i:i+2] == '||':
                tokens.append('||')
                i += 2
            elif expr[i:i+2] == '&&':
                tokens.append('&&')
                i += 2
            else:
                atom, end = self._read_atom(expr, i)
                tokens.append(atom)
                i = end
        return tokens

    def _read_atom(self, expr, start):
        """Read an atom (word, subsystem ref, or var test) starting at position."""
        i = start
        while i < len(expr) and expr[i] not in ' \t\n\r()':
            if expr[i:i+2] in ('||', '&&'):
                break
            # Allow != within atoms (for var tests like CPUBOARD!=IP26)
            if expr[i] == '!' and i + 1 < len(expr) and expr[i + 1] == '=':
                i += 2
                continue
            i += 1
        return expr[start:i].strip(), i

    def _peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _consume(self, expected=None):
        tok = self.tokens[self.pos]
        if expected and tok != expected:
            raise ValueError(f"Expected {expected}, got {tok}")
        self.pos += 1
        return tok

    def _parse_or(self):
        left = self._parse_and()
        while self._peek() == '||':
            self._consume('||')
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self):
        left = self._parse_unary()
        while self._peek() == '&&':
            self._consume('&&')
            right = self._parse_unary()
            left = left and right
        return left

    def _parse_unary(self):
        if self._peek() == '!':
            self._consume('!')
            return not self._parse_unary()
        if self._peek() == '(':
            self._consume('(')
            result = self._parse_or()
            if self._peek() == ')':
                self._consume(')')
            return result
        return self._parse_atom()

    def _parse_atom(self):
        tok = self._consume()
        # Variable test: DMODE=64bit, CPUBOARD!=IP26, GFXBOARD!=SERVER
        if self._VAR_TEST_RE.match(tok):
            return _eval_single_test(tok, self.target)
        # Subsystem reference: product.type.subsystem
        if self._SUBSYS_RE.match(tok):
            return tok in self.available
        # Special literal: "noship" is always False
        if tok.lower() == 'noship':
            return False
        # Unknown literal — conservatively True
        return True


# ── inst Simulator: IDB Hardware Parser ──────────────────────────

def parse_idb_hardware(idb_text, target):
    """Parse IDB file text and evaluate mach() per-subsystem for a target.

    Returns dict: {subsystem_name: {
        'total_files': int, 'total_size': int,
        'target_files': int, 'target_size': int,
        'fully_excluded': bool
    }}
    """
    subsystems = defaultdict(lambda: {
        'total_files': 0, 'total_size': 0,
        'target_files': 0, 'target_size': 0,
    })

    mach_re = re.compile(r'mach\(([^)]*)\)')
    size_re = re.compile(r'(?<![a-z])size\((\d+)\)')

    for line in idb_text.split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        entry_type = parts[0]
        if entry_type not in ('d', 'f', 'l', 'c', 'b', 'p'):
            continue

        subsystem = parts[-1]
        # Validate subsystem name format
        if '.' not in subsystem:
            # Last field isn't a subsystem — try field 6 (0-indexed)
            subsystem = parts[6]
            if '.' not in subsystem:
                continue

        info = subsystems[subsystem]
        info['total_files'] += 1

        # Extract size
        rest = ' '.join(parts[7:])
        size_m = size_re.search(rest)
        file_size = int(size_m.group(1)) if size_m else 0
        info['total_size'] += file_size

        # Check mach() restriction
        mach_m = mach_re.search(rest)
        if mach_m:
            if eval_mach_expr(mach_m.group(1), target):
                info['target_files'] += 1
                info['target_size'] += file_size
        else:
            # No mach() restriction — file is for all platforms
            info['target_files'] += 1
            info['target_size'] += file_size

    # Determine fully_excluded
    result = {}
    for subsys, info in subsystems.items():
        info['fully_excluded'] = (info['target_files'] == 0
                                  and info['total_files'] > 0)
        result[subsys] = info

    return result


def extract_subsystem_deps(spec_data):
    """Extract per-subsystem dependency expressions from spec file bytes.

    Scans for length-prefixed subsystem names followed by length-prefixed
    dependency expressions containing operators (&&, ||) or known keywords
    (noship, CPUBOARD, DMODE, GFXBOARD, MODE).

    Returns dict: {subsystem_name: dep_expression_string}
    """
    if len(spec_data) < 20 or spec_data[:5] != b'pd001':
        return {}

    subsys_re = re.compile(
        rb'^[a-zA-Z_][\w+]*\.\w+\.\w+$')
    dep_indicators = (b'&&', b'||', b'noship', b'CPUBOARD', b'DMODE',
                      b'GFXBOARD', b'MODE=', b'SUBGR', b'CPUARCH')

    deps = {}

    # Find all length-prefixed subsystem names (null-terminated after)
    i = 20  # Skip header
    while i < len(spec_data) - 2:
        length = spec_data[i]
        if 8 <= length <= 100 and i + 1 + length < len(spec_data):
            candidate = spec_data[i + 1:i + 1 + length]
            if (spec_data[i + 1 + length] == 0
                    and all(0x20 <= b < 0x7f for b in candidate)
                    and subsys_re.match(candidate)):
                subsys_name = candidate.decode('ascii')

                # Scan forward for dependency expression (up to 500 bytes)
                search_start = i + 1 + length + 1
                j = search_start
                while j < min(search_start + 500, len(spec_data) - 2):
                    dep_len = spec_data[j]
                    if 8 <= dep_len <= 250 and j + 1 + dep_len <= len(spec_data):
                        dep_candidate = spec_data[j + 1:j + 1 + dep_len]
                        if all(0x20 <= b < 0x7f for b in dep_candidate):
                            dep_text = dep_candidate.decode('ascii').strip()
                            if any(ind in dep_candidate for ind in dep_indicators):
                                deps[subsys_name] = dep_text
                                break
                            # Also check for bare subsystem refs as prereqs
                            if re.match(
                                    r'^[a-zA-Z_]\w*\.\w+\.\w+'
                                    r'(\s*\|\|\s*[a-zA-Z_]\w*\.\w+\.\w+)*$',
                                    dep_text):
                                deps[subsys_name] = dep_text
                                break
                    j += 1

                i = i + 1 + length + 1
                continue
        i += 1

    return deps


# ── inst Simulator: Core ─────────────────────────────────────────

class InstSimulator:
    """Simulates 'inst' keep * + install standard for conflict prediction.

    Predicts inst conflicts before building a combined distribution image
    by parsing spec and IDB files to check prerequisites and hardware
    restrictions against a target system configuration.
    """

    def __init__(self, target_name, verbose=False):
        if target_name not in TARGET_CONFIGS:
            raise ValueError(
                "Unknown target %r. Known: %s"
                % (target_name, ", ".join(sorted(TARGET_CONFIGS))))
        self.target_name = target_name
        self.target = TARGET_CONFIGS[target_name]
        self.verbose = verbose

        # Populated by load_*
        self._products = {}         # product_name -> ProductInfo
        self._subsystem_idb = {}    # subsystem_name -> idb hw info dict
        self._subsystem_deps = {}   # subsystem_name -> dep expression string
        self._all_subsystems = set()

    def load_dist(self, dist_path):
        """Load products from an extracted dist directory."""
        dist_path = Path(dist_path)
        if not dist_path.exists():
            raise FileNotFoundError(f"Dist directory not found: {dist_path}")

        scanner = CDScanner()
        cd = scanner.scan_directory(dist_path)

        for product in cd.products:
            self._products[product.product_name] = product
            for sub in product.subsystem_names:
                self._all_subsystems.add(sub)

        # Parse IDB files for hardware info
        for entry in sorted(dist_path.iterdir()):
            if not entry.name.endswith('.idb') or not entry.is_file():
                continue
            try:
                text = entry.read_text(encoding='latin-1', errors='replace')
            except OSError:
                continue
            hw_info = parse_idb_hardware(text, self.target)
            self._subsystem_idb.update(hw_info)

        # Parse spec files for per-subsystem dep expressions
        for entry in sorted(dist_path.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix.lower() in CDScanner._SKIP_EXT:
                continue
            try:
                data = entry.read_bytes()
            except OSError:
                continue
            if len(data) < 20 or data[:5] != b'pd001':
                continue
            deps = extract_subsystem_deps(data)
            self._subsystem_deps.update(deps)

    def load_image(self, image_path):
        """Load products from an EFS disk image."""
        image_path = Path(image_path)
        efs_scanner = EFSImageScanner()
        er = efs_scanner._get_efs()

        try:
            f = open(image_path, 'rb')
        except OSError as e:
            raise FileNotFoundError(f"Cannot open image: {e}")

        try:
            result = er.find_efs_partition(f)
            if not result:
                raise ValueError(f"No EFS partition in {image_path.name}")

            part_offset, part_size = result
            sb = er.read_superblock(f, part_offset)
            if not sb:
                raise ValueError(f"Invalid EFS superblock in {image_path.name}")

            root_inode = er.read_inode(
                f, part_offset, sb, er.EFS_ROOT_INODE)
            if not root_inode:
                raise ValueError("Cannot read root inode")

            # Find all spec and idb files
            specs_found = []
            efs_scanner._find_specs_recursive(
                f, er, part_offset, sb, er.EFS_ROOT_INODE, '',
                specs_found, max_depth=6)

            # Process specs
            for spec_name, spec_data, dir_entries, _path in specs_found:
                product = SpecFileParser.parse_bytes(
                    spec_data, spec_name, cd_source=image_path.name)
                if not product:
                    continue
                if product.product_name in self._products:
                    continue
                self._products[product.product_name] = product

                # Extract per-subsystem deps from spec data
                deps = extract_subsystem_deps(spec_data)
                self._subsystem_deps.update(deps)

                # Try to load companion .idb
                idb_name = spec_name + '.idb'
                for idb_entry_name, idb_ino in dir_entries:
                    if idb_entry_name == idb_name:
                        idb_inode = er.read_inode(
                            f, part_offset, sb, idb_ino)
                        if idb_inode:
                            idb_data = er.read_file_data(
                                f, part_offset, sb, idb_inode)
                            if idb_data:
                                text = idb_data.decode(
                                    'latin-1', errors='replace')
                                # Parse subsystem names
                                product.subsystem_names = \
                                    efs_scanner._parse_idb_bytes(idb_data)
                                # Parse hardware info
                                hw_info = parse_idb_hardware(
                                    text, self.target)
                                self._subsystem_idb.update(hw_info)
                        break

                for sub in product.subsystem_names:
                    self._all_subsystems.add(sub)
        finally:
            f.close()

    def simulate(self):
        """Run keep * + install standard simulation.

        Returns SimulationResult with detected conflicts.
        """
        result = SimulationResult(
            target=self.target,
            target_name=self.target_name,
            total_products=len(self._products),
        )

        # Build full subsystem set from IDB data and product records
        all_subs = set(self._all_subsystems)
        for info in self._subsystem_idb:
            all_subs.add(info)
        result.total_subsystems = len(all_subs)

        # Select defaults: .sw subsystems, plus .sw64 if 64bit mode
        selected = set()
        for sub in all_subs:
            parts = sub.split('.')
            if len(parts) >= 2:
                sub_type = parts[1]  # e.g., "sw", "man", "books"
                if sub_type == 'sw':
                    selected.add(sub)
                elif sub_type == 'sw64' and self.target.mode == '64bit':
                    selected.add(sub)
                elif sub_type == 'sw32' and self.target.mode == '32bit':
                    selected.add(sub)

        result.selected_subsystems = len(selected)

        # Build records and check for conflicts
        conflicts = []
        hw_excluded = 0
        install_size = 0
        records = []

        for sub in sorted(selected):
            parts = sub.split('.')
            product = parts[0] if parts else sub
            sub_type = parts[1] if len(parts) > 1 else ''

            rec = SubsystemRecord(
                name=sub,
                product=product,
                subsys_type=sub_type,
                is_default=True,
            )

            # Fill in IDB hardware info
            idb = self._subsystem_idb.get(sub)
            if idb:
                rec.total_files = idb['total_files']
                rec.total_size = idb['total_size']
                rec.target_files = idb['target_files']
                rec.target_size = idb['target_size']
                rec.fully_excluded = idb['fully_excluded']

                if rec.fully_excluded:
                    hw_excluded += 1
                    conflicts.append(InstConflict(
                        conflict_type='hw_excluded',
                        subsystem=sub,
                        detail=(f"{sub} -- {rec.total_files} files, "
                                f"0 for {self.target.cpuboard}"),
                        resolution=f"do not install {sub}",
                    ))
                else:
                    install_size += rec.target_size

            # Fill in dep expression
            dep_expr = self._subsystem_deps.get(sub, '')
            rec.dep_expression = dep_expr

            if dep_expr and not rec.fully_excluded:
                parser = DepExprParser(self._all_subsystems, self.target)
                if not parser.evaluate(dep_expr):
                    # Determine what's missing
                    missing = self._find_missing_refs(dep_expr)
                    hw_fail = self._find_hw_fail(dep_expr)

                    if hw_fail:
                        conflicts.append(InstConflict(
                            conflict_type='hw_restricted',
                            subsystem=sub,
                            detail=f"{sub} requires {hw_fail}",
                            resolution=f"do not install {sub}",
                        ))
                    elif missing:
                        conflicts.append(InstConflict(
                            conflict_type='missing_prereq',
                            subsystem=sub,
                            detail=(f"{sub} requires "
                                    f"{', '.join(missing[:3])}"
                                    f"{' ...' if len(missing) > 3 else ''}"),
                            resolution=f"do not install {sub}",
                        ))

            records.append(rec)

        result.hw_excluded_subsystems = hw_excluded
        result.conflicts = conflicts
        result.install_size = install_size
        result.subsystem_records = records

        return result

    def _find_missing_refs(self, dep_expr):
        """Extract subsystem references from a dep expr that aren't available."""
        refs = re.findall(
            r'[a-zA-Z_]\w*\.\w+\.\w+', dep_expr)
        return [r for r in refs if r not in self._all_subsystems]

    def _find_hw_fail(self, dep_expr):
        """Check if a dep expression fails due to hardware restrictions."""
        # Look for VAR=VAL or VAR!=VAL patterns
        tests = re.findall(
            r'[A-Z][A-Z0-9_]*[!=]+=?\w+', dep_expr)
        for test in tests:
            if not _eval_single_test(test, self.target):
                return test
        return None


# ── Spec File Parser ─────────────────────────────────────────────
# TODO(pyirix): The binary cursor-reader pattern (_SpecReader) is independently
# implemented in dist/parser.py and dist/patch.py (_R class). Consolidate into
# a shared utility when the interfaces converge.

class SpecFileParser:
    """Parses IRIX product descriptor (spec) binary files.

    Format:
      Offset 0:  "pd001" magic (5 bytes)
      Offset 5:  V-code "V630"/"V650"/"V620" (4 bytes)
      Offset 9:  P-code "P00"/"P02" (3 bytes)
      ~Offset 22: Length-prefixed product name
      After name: Length-prefixed description
      Variable:   Product ID "P<build_ts>_<version_ts>" (V630/V650)
    """

    # Product ID pattern: P followed by digits, underscore, digits
    _PID_RE = re.compile(rb'P(\d{5,})_(\d{8,})')

    # Version suffix stripping for canonical product names
    _VERSUFFIX_RE = re.compile(r'_\d+_\d+[a-z]*$|_\d+[a-z]*$')

    @classmethod
    def parse(cls, path: Path, cd_source: str = '') -> Optional[ProductInfo]:
        """Parse a spec file and extract product metadata.

        Returns ProductInfo or None if the file is not a valid spec.
        """
        try:
            with open(path, 'rb') as f:
                data = f.read(min(os.path.getsize(path), 512))
        except (OSError, PermissionError):
            return None

        if len(data) < 20 or data[:5] != b'pd001':
            return None

        v_code = data[5:9].decode('ascii', errors='replace')
        spec_filename = path.stem if path.suffix else path.name

        # Extract product name and description from length-prefixed strings
        product_name, description = cls._extract_strings(data)
        if not product_name:
            return None

        # Canonical product name: strip version suffixes
        canonical = cls._VERSUFFIX_RE.sub('', spec_filename)

        # Extract product ID and version timestamp
        product_id = None
        version_ts = None

        m = cls._PID_RE.search(data[:300])
        if m:
            product_id = m.group(0).decode('ascii')
            version_ts = int(m.group(2))
        # V620 files don't have reliable ASCII product IDs;
        # leave version_ts as None rather than risk false matches

        # Load subsystem names from companion .idb file
        subsystem_names = []
        idb_path = path.parent / (spec_filename + '.idb')
        if idb_path.exists():
            subs = parse_idb_subsystems(idb_path)
            subsystem_names = sorted(subs.keys())

        # Load dependency references from the spec file itself
        dep_references = []
        deps = extract_deps_from_spec(path)
        for dep in deps:
            dep_references.extend(dep.get("references", []))
        dep_references = sorted(set(dep_references))

        return ProductInfo(
            spec_filename=spec_filename,
            product_name=canonical,
            description=description,
            v_code=v_code,
            version_ts=version_ts,
            product_id=product_id,
            cd_source=cd_source,
            subsystem_names=subsystem_names,
            dep_references=dep_references,
        )

    @staticmethod
    def _extract_strings(data: bytes) -> tuple:
        """Extract product name and description from spec file header.

        Scans for the first two length-prefixed ASCII strings starting
        around offset 18-25 (after the fixed header and preamble bytes).
        """
        # The header has ~10 bytes of binary data after offset 12,
        # then length-prefixed strings. Scan from offset 18 onward.
        strings_found = []
        i = 18
        limit = min(len(data), 300)

        while i < limit and len(strings_found) < 2:
            # Skip null bytes
            if data[i] == 0:
                i += 1
                continue

            length = data[i]
            if length == 0 or i + 1 + length > limit:
                i += 1
                continue

            candidate = data[i + 1:i + 1 + length]
            # Check if it's printable ASCII (allow some high bytes for
            # description strings that may have special chars)
            printable = sum(1 for b in candidate if 0x20 <= b < 0x7f)
            if printable >= len(candidate) * 0.8 and len(candidate) >= 2:
                text = candidate.decode('latin-1', errors='replace').strip()
                strings_found.append(text)
                i += 1 + length
            else:
                i += 1

        product_name = strings_found[0] if len(strings_found) > 0 else ""
        description = strings_found[1] if len(strings_found) > 1 else ""
        # Clean description (may have leading length byte artifact)
        if description and not description[0].isalpha() and len(description) > 1:
            description = description[1:]
        return product_name, description



# ── CD Scanner ───────────────────────────────────────────────────

class CDScanner:
    """Scans an extracted dist directory and catalogs all products."""

    # Extensions that are NOT spec files
    _SKIP_EXT = {'.idb', '.sw', '.sw32', '.sw64', '.man', '.books',
                 '.data', '.src', '.hdr', '.relnotes', '.help',
                 '.redirect', '.iscd'}

    def scan_directory(self, path: Path, name: str = '') -> CDInfo:
        """Scan a directory for spec files and build CDInfo."""
        if not name:
            name = path.name

        cd = CDInfo(name=name, path=path)
        products = []

        if not path.exists():
            return cd

        for entry in sorted(path.iterdir()):
            if not entry.is_file():
                continue
            # Skip files with known non-spec extensions
            if entry.suffix.lower() in self._SKIP_EXT:
                continue
            # Skip hidden files
            if entry.name.startswith('.'):
                continue
            # Skip very large files (data, not specs)
            try:
                if entry.stat().st_size > 1_000_000:
                    continue
                if entry.stat().st_size == 0:
                    continue
            except OSError:
                continue

            product = SpecFileParser.parse(entry, cd_source=name)
            if product:
                products.append(product)

        cd.products = products

        # Compute median timestamp and detect version family
        timestamps = [p.version_ts for p in products if p.version_ts]
        if timestamps:
            timestamps.sort()
            cd.median_timestamp = timestamps[len(timestamps) // 2]

        cd.version_family = self._detect_family(cd)
        return cd

    @staticmethod
    def _detect_family(cd: CDInfo) -> str:
        """Detect the version family based on V-code and timestamps."""
        if not cd.products:
            return "unknown"

        v_codes = defaultdict(int)
        for p in cd.products:
            v_codes[p.v_code] += 1

        dominant_v = max(v_codes, key=v_codes.get) if v_codes else "?"
        ts = cd.median_timestamp

        if ts is None:
            if dominant_v == 'V620':
                return "compiler-v620"
            return "unknown"

        # Classify based on dominant V-code and timestamp ranges
        # Foundation CDs: V630, timestamps ~1274627333 (May 2010)
        # 6.5.5 Overlays: V650, timestamps ~1275719120 (Jun 2010)
        # 6.5.22 Overlays: V650, timestamps ~1289434520 (Nov 2010)
        # Applications: V630, timestamps ~1274627333 (May 2010)
        # 6.5.30 Overlays: V650, timestamps > 1300000000

        date_str = time.strftime('%Y-%m', time.gmtime(ts))

        if dominant_v == 'V650':
            if ts > 1300000000:
                return "6.5.30-overlay"
            elif ts > 1285000000:
                return "6.5.22-overlay"
            elif ts > 1270000000:
                return "6.5.5-overlay"
            else:
                return f"overlay-{date_str}"
        elif dominant_v == 'V630':
            # Distinguish foundation from applications by product names and CD name
            product_names = {p.product_name for p in cd.products}
            name_lower = cd.name.lower()
            if ('eoe' in product_names or 'x_eoe' in product_names
                    or 'foundation' in name_lower):
                return "6.5-foundation"
            else:
                return "6.5-applications"
        elif dominant_v == 'V620':
            return "compiler-v620"

        return f"unknown-{dominant_v}-{date_str}"


# ── EFS Image Scanner ───────────────────────────────────────────

class EFSImageScanner:
    """Scans EFS disk images (SGI CD-ROMs) for product metadata.

    Reads spec files directly from the EFS filesystem inside .img files,
    without needing to extract them to disk first. Uses efs_reader for
    filesystem traversal and read_file_data for content extraction.
    """

    def __init__(self):
        # Lazy import efs_reader -- only needed when scanning images
        self._efs = None

    def _get_efs(self):
        if self._efs is None:
            import efs_reader
            self._efs = efs_reader
        return self._efs

    # Extensions that are NOT spec files (same as CDScanner)
    _SKIP_EXT = {'.idb', '.sw', '.sw32', '.sw64', '.man', '.books',
                 '.data', '.src', '.hdr', '.relnotes', '.help',
                 '.redirect', '.iscd', '.doc'}

    def scan_image(self, image_path: Path,
                   name: str = '') -> Optional[CDInfo]:
        """Scan an EFS disk image for product spec files.

        Opens the image, finds the EFS partition, locates the dist/
        directory, and reads spec file contents to build a CDInfo.

        Returns CDInfo or None if the image can't be read.
        """
        er = self._get_efs()
        image_path = Path(image_path)
        if not name:
            name = self._clean_image_name(image_path)

        try:
            f = open(image_path, 'rb')
        except OSError as e:
            print(f"  Cannot open {image_path}: {e}", file=sys.stderr)
            return None

        try:
            return self._scan_open_image(f, er, image_path, name)
        finally:
            f.close()

    def _scan_open_image(self, f, er, image_path, name):
        """Scan an already-opened EFS image file.

        Searches the entire filesystem recursively for spec files (pd001
        magic).  SGI CD-ROMs use several different layouts:

        1. /dist/<spec>                   -- standard (most discs)
        2. /dist/<subdir>/<spec>          -- nested (Dev Foundation, IDO 7.1,
                                             Compiler Exec Env, etc.)
        3. Arbitrary deep paths           -- /install/demos_O2, /toolbox/...,
                                             /public/GNU/emacs.inst/emacs19

        A recursive walk catches all three without hard-coding paths.  To
        avoid counting the same product twice (some discs duplicate specs
        across version subdirs like dist6.3/, dist6.4/, dist6.5/), we
        deduplicate by product_name, keeping the first occurrence found.

        See progress_notes/irix_cd_directory_layouts.md for the full
        taxonomy of disc layouts discovered across 207 images.
        """
        # Find EFS partition
        result = er.find_efs_partition(f)
        if not result:
            print(f"  No EFS partition in {image_path.name}",
                  file=sys.stderr)
            return None

        part_offset, part_size = result
        sb = er.read_superblock(f, part_offset)
        if not sb:
            print(f"  Invalid EFS superblock in {image_path.name}",
                  file=sys.stderr)
            return None

        root_inode = er.read_inode(f, part_offset, sb, er.EFS_ROOT_INODE)
        if not root_inode:
            return None

        # Recursively find all spec files and their sibling .idb files
        specs_found = []  # [(spec_name, spec_data, dir_entries, path)]
        self._find_specs_recursive(
            f, er, part_offset, sb, er.EFS_ROOT_INODE, '', specs_found,
            max_depth=6)

        # Parse specs, dedup by product_name (keep first seen)
        products = []
        seen_products = set()
        for spec_name, spec_data, dir_entries, _path in specs_found:
            product = SpecFileParser.parse_bytes(
                spec_data, spec_name, cd_source=name)
            if not product:
                continue
            if product.product_name in seen_products:
                continue
            seen_products.add(product.product_name)

            # Try to load subsystem names from companion .idb
            idb_name = spec_name + '.idb'
            for idb_entry_name, idb_ino in dir_entries:
                if idb_entry_name == idb_name:
                    idb_inode = er.read_inode(
                        f, part_offset, sb, idb_ino)
                    if idb_inode:
                        idb_data = er.read_file_data(
                            f, part_offset, sb, idb_inode)
                        if idb_data:
                            product.subsystem_names = \
                                self._parse_idb_bytes(idb_data)
                    break
            products.append(product)

        cd = CDInfo(name=name, path=image_path, products=products)

        # Compute median timestamp and family
        timestamps = [p.version_ts for p in products if p.version_ts]
        if timestamps:
            timestamps.sort()
            cd.median_timestamp = timestamps[len(timestamps) // 2]
        cd.version_family = CDScanner._detect_family(cd)

        return cd

    def _find_specs_recursive(self, f, er, part_offset, sb,
                              dir_ino, path, results, max_depth):
        """Recursively walk directories to find spec files.

        For each regular file, checks for pd001 magic.  Collects the
        file's directory entry list (siblings) so the caller can find
        companion .idb files.
        """
        if max_depth <= 0:
            return

        dir_inode = er.read_inode(f, part_offset, sb, dir_ino)
        if not dir_inode:
            return
        if (dir_inode['mode'] & 0o170000) != 0o040000:
            return

        entries = er.read_dir_entries(f, part_offset, sb, dir_inode)

        for entry_name, ino in entries:
            if entry_name.startswith('.'):
                continue

            inode = er.read_inode(f, part_offset, sb, ino)
            if not inode:
                continue

            ftype = inode['mode'] & 0o170000

            if ftype == 0o040000:
                # Recurse into subdirectory
                child_path = path + '/' + entry_name if path else entry_name
                self._find_specs_recursive(
                    f, er, part_offset, sb, ino, child_path,
                    results, max_depth - 1)

            elif ftype == 0o100000:
                # Regular file -- check if it's a spec
                suffix = Path(entry_name).suffix.lower()
                if suffix in self._SKIP_EXT:
                    continue
                if inode['size'] > 1_000_000 or inode['size'] < 20:
                    continue

                try:
                    data = er.read_file_data(f, part_offset, sb, inode)
                except Exception:
                    continue
                if not data or len(data) < 20:
                    continue
                if data[:5] != b'pd001':
                    continue

                results.append((entry_name, data, entries, path))

    @staticmethod
    def _clean_image_name(path: Path) -> str:
        """Derive a clean display name from an image filename."""
        name = path.stem
        # Remove common suffixes
        for suffix in ['.efs', '.img']:
            if name.lower().endswith(suffix):
                name = name[:-len(suffix)]
        # Truncate at 50 chars
        if len(name) > 50:
            name = name[:47] + '...'
        return name

    @staticmethod
    def _parse_idb_bytes(data: bytes) -> list:
        """Parse subsystem names from .idb file contents in memory.

        IDB format: type perms owner group install_path src_path [attrs...] subsystem
        The subsystem name is always the LAST field and matches product.type.name.
        """
        subsystems = set()
        subsys_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_+]*\.\w+\.\w+')
        try:
            text = data.decode('latin-1', errors='replace')
            for line in text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 7:
                    continue
                if parts[0] not in ('d', 'f', 'l', 'c', 'b', 'p'):
                    continue
                # Subsystem name is the last field
                candidate = parts[-1]
                if subsys_re.match(candidate):
                    subsystems.add(candidate)
        except Exception:
            pass
        return sorted(subsystems)


# Add parse_bytes class method to SpecFileParser
_orig_parse = SpecFileParser.parse


@classmethod
def _parse_bytes(cls, data: bytes, filename: str,
                 cd_source: str = '') -> Optional[ProductInfo]:
    """Parse spec file metadata from raw bytes (no disk file needed).

    Used by EFSImageScanner to parse spec files read from EFS images.
    """
    if len(data) < 20 or data[:5] != b'pd001':
        return None

    v_code = data[5:9].decode('ascii', errors='replace')
    spec_filename = filename

    # Canonical product name: strip version suffixes
    canonical = cls._VERSUFFIX_RE.sub('', spec_filename)

    # Extract product name and description
    product_name, description = cls._extract_strings(data)
    if not product_name:
        return None

    # Extract product ID and version timestamp
    product_id = None
    version_ts = None
    m = cls._PID_RE.search(data[:300])
    if m:
        product_id = m.group(0).decode('ascii')
        version_ts = int(m.group(2))

    # Extract dependency references from the spec data
    dep_references = []
    deps = _extract_deps_from_bytes(data)
    for dep in deps:
        dep_references.extend(dep.get("references", []))
    dep_references = sorted(set(dep_references))

    return ProductInfo(
        spec_filename=spec_filename,
        product_name=canonical,
        description=description,
        v_code=v_code,
        version_ts=version_ts,
        product_id=product_id,
        cd_source=cd_source,
        subsystem_names=[],  # filled in by caller from .idb
        dep_references=dep_references,
    )


SpecFileParser.parse_bytes = _parse_bytes


def _extract_deps_from_bytes(data: bytes) -> list:
    """Extract dependency expressions from spec file bytes.

    Same logic as dist_analyzer.extract_deps_from_spec but works on
    raw bytes instead of a file path.
    """
    deps = []
    # Find all readable strings
    text_regions = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= 8:
                text_regions.append((start, ''.join(current)))
            current = []
    if len(current) >= 8:
        text_regions.append((start, ''.join(current)))

    subsys_pattern = re.compile(
        r'[a-zA-Z_][a-zA-Z0-9_]*\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*')
    for offset, text in text_regions:
        matches = subsys_pattern.findall(text)
        if matches:
            deps.append({
                "offset": offset,
                "expression": text.strip(),
                "references": list(set(matches)),
            })
    return deps


# ── Package Database ─────────────────────────────────────────────

class PackageDatabase:
    """SQLite cache for EFS image scan results.

    Stores product/subsystem/dependency metadata keyed by MD5 hash of
    image files. Enables instant lookups on repeat scans since image
    contents never change.
    """

    DEFAULT_PATH = PROJECT_ROOT / "software_library" / "irix_packages.db"

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else self.DEFAULT_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS images (
                md5_hash TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_size INTEGER,
                scan_date TEXT NOT NULL,
                version_family TEXT,
                median_timestamp INTEGER,
                dominant_vcode TEXT,
                product_count INTEGER
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_hash TEXT NOT NULL REFERENCES images(md5_hash) ON DELETE CASCADE,
                spec_filename TEXT NOT NULL,
                product_name TEXT NOT NULL,
                description TEXT,
                v_code TEXT,
                version_ts INTEGER,
                product_id TEXT
            );
            CREATE TABLE IF NOT EXISTS subsystems (
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dep_references (
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                ref_name TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_products_image ON products(image_hash);
            CREATE INDEX IF NOT EXISTS idx_products_name ON products(product_name);
            CREATE INDEX IF NOT EXISTS idx_subsystems_product ON subsystems(product_id);
            CREATE INDEX IF NOT EXISTS idx_dep_refs_product ON dep_references(product_id);
        """)

    def compute_hash(self, path: Path) -> str:
        """Compute MD5 hash of a file, reading in 1MB chunks."""
        h = hashlib.md5()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def lookup(self, md5_hash: str) -> Optional[CDInfo]:
        """Load cached CDInfo from DB. Returns None if not found."""
        row = self.conn.execute(
            "SELECT filename, version_family, median_timestamp "
            "FROM images WHERE md5_hash = ?", (md5_hash,)
        ).fetchone()
        if not row:
            return None

        filename, version_family, median_ts = row
        products = []
        for prow in self.conn.execute(
            "SELECT id, spec_filename, product_name, description, "
            "v_code, version_ts, product_id FROM products "
            "WHERE image_hash = ?", (md5_hash,)
        ):
            pid, spec_fn, pname, desc, vcode, vts, prodid = prow
            subs = [r[0] for r in self.conn.execute(
                "SELECT name FROM subsystems WHERE product_id = ?", (pid,)
            )]
            deps = [r[0] for r in self.conn.execute(
                "SELECT ref_name FROM dep_references WHERE product_id = ?",
                (pid,)
            )]
            products.append(ProductInfo(
                spec_filename=spec_fn,
                product_name=pname,
                description=desc or "",
                v_code=vcode or "",
                version_ts=vts,
                product_id=prodid,
                cd_source=filename,
                subsystem_names=sorted(subs),
                dep_references=sorted(deps),
            ))

        cd = CDInfo(
            name=filename,
            path=Path(filename),
            products=products,
            version_family=version_family or "",
            median_timestamp=median_ts,
        )
        return cd

    def store(self, md5_hash: str, filename: str, file_size: int,
              cd: CDInfo):
        """Store a CDInfo in the database."""
        # Determine dominant v-code
        vcodes = defaultdict(int)
        for p in cd.products:
            vcodes[p.v_code] += 1
        dominant = max(vcodes, key=vcodes.get) if vcodes else None

        scan_date = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())

        with self.conn:
            # Delete any existing entry (re-scan)
            self.conn.execute(
                "DELETE FROM images WHERE md5_hash = ?", (md5_hash,))
            self.conn.execute(
                "INSERT INTO images (md5_hash, filename, file_size, "
                "scan_date, version_family, median_timestamp, "
                "dominant_vcode, product_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (md5_hash, filename, file_size, scan_date,
                 cd.version_family, cd.median_timestamp, dominant,
                 len(cd.products))
            )
            for p in cd.products:
                cur = self.conn.execute(
                    "INSERT INTO products (image_hash, spec_filename, "
                    "product_name, description, v_code, version_ts, "
                    "product_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (md5_hash, p.spec_filename, p.product_name,
                     p.description, p.v_code, p.version_ts, p.product_id)
                )
                pid = cur.lastrowid
                for sub in p.subsystem_names:
                    self.conn.execute(
                        "INSERT INTO subsystems (product_id, name) "
                        "VALUES (?, ?)", (pid, sub))
                for dep in p.dep_references:
                    self.conn.execute(
                        "INSERT INTO dep_references (product_id, ref_name) "
                        "VALUES (?, ?)", (pid, dep))

    def scan_or_lookup(self, image_path: Path) -> Optional[CDInfo]:
        """Compute hash, check DB, scan EFS if cache miss, store result.

        Returns (CDInfo, was_cached) tuple.
        """
        md5 = self.compute_hash(image_path)
        cached = self.lookup(md5)
        if cached:
            # Update path to actual location
            cached.path = image_path
            return cached
        scanner = EFSImageScanner()
        cd = scanner.scan_image(image_path)
        if cd:
            self.store(md5, image_path.name, image_path.stat().st_size, cd)
        return cd

    def is_cached(self, image_path: Path) -> bool:
        """Check if an image is already in the database."""
        md5 = self.compute_hash(image_path)
        row = self.conn.execute(
            "SELECT 1 FROM images WHERE md5_hash = ?", (md5,)
        ).fetchone()
        return row is not None

    def list_images(self) -> list:
        """Return all scanned images with summary info."""
        rows = self.conn.execute(
            "SELECT md5_hash, filename, file_size, scan_date, "
            "version_family, median_timestamp, dominant_vcode, "
            "product_count FROM images ORDER BY filename"
        ).fetchall()
        return [
            {
                'md5_hash': r[0], 'filename': r[1], 'file_size': r[2],
                'scan_date': r[3], 'version_family': r[4],
                'median_timestamp': r[5], 'dominant_vcode': r[6],
                'product_count': r[7],
            }
            for r in rows
        ]

    def get_image_products(self, md5_hash: str) -> list:
        """Return all products for an image."""
        rows = self.conn.execute(
            "SELECT spec_filename, product_name, description, v_code, "
            "version_ts, product_id FROM products WHERE image_hash = ? "
            "ORDER BY product_name", (md5_hash,)
        ).fetchall()
        return [
            {
                'spec_filename': r[0], 'product_name': r[1],
                'description': r[2], 'v_code': r[3],
                'version_ts': r[4], 'product_id': r[5],
            }
            for r in rows
        ]

    def find_by_hash_prefix(self, prefix: str) -> Optional[str]:
        """Find a full hash from a prefix (first 8+ chars)."""
        rows = self.conn.execute(
            "SELECT md5_hash FROM images WHERE md5_hash LIKE ?",
            (prefix + '%',)
        ).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        return None

    def close(self):
        self.conn.close()


# ── Conflict Analyzer ────────────────────────────────────────────

class ConflictAnalyzer:
    """Analyzes a set of CDs for version conflicts and compatibility."""

    def analyze(self, cds: list) -> ConflictReport:
        """Run full analysis on a list of CDInfo objects."""
        report = ConflictReport()
        report.version_conflicts = self.find_version_conflicts(cds)
        report.prerequisite_gaps = self.find_prerequisite_gaps(cds)
        report.family_mismatches = self.check_family_compatibility(cds)

        # Determine if safe to combine
        has_conflicts = any(c.resolution == "conflict"
                           for c in report.version_conflicts)
        has_errors = any(m.severity == "error"
                         for m in report.family_mismatches)
        report.safe_to_combine = not has_conflicts and not has_errors

        # Generate recommendations
        if has_conflicts:
            report.recommendations.append(
                "Version conflicts detected -- overlay versions should be "
                "newer than foundation versions. Check CD set compatibility.")
        if has_errors:
            report.recommendations.append(
                "Family mismatch errors -- CDs may be from different IRIX "
                "releases. Verify CD labels match intended configuration.")
        if not has_conflicts and not has_errors:
            report.recommendations.append(
                "All version overlaps are normal (overlay supersedes foundation). "
                "CD set is compatible.")

        return report

    def find_version_conflicts(self, cds: list) -> list:
        """Find products that appear on multiple CDs with different versions."""
        # Group products by canonical name across all CDs
        product_map = defaultdict(list)
        for cd in cds:
            for product in cd.products:
                product_map[product.product_name].append(
                    (cd.name, product.version_ts, product.spec_filename,
                     product.v_code))

        conflicts = []
        for name, entries in sorted(product_map.items()):
            if len(entries) <= 1:
                continue

            # Deduplicate by CD (same product shouldn't appear twice on same CD)
            seen_cds = set()
            unique_entries = []
            for entry in entries:
                if entry[0] not in seen_cds:
                    seen_cds.add(entry[0])
                    unique_entries.append(entry)

            if len(unique_entries) <= 1:
                continue

            conflict = VersionConflict(
                product_name=name,
                entries=[(e[0], e[1], e[2]) for e in unique_entries],
            )

            # Classify the conflict
            timestamps = [e[1] for e in unique_entries if e[1] is not None]
            v_codes = [e[3] for e in unique_entries]
            has_none_ts = any(e[1] is None for e in unique_entries)

            if not timestamps:
                conflict.resolution = "unknown"
            elif len(set(timestamps)) == 1 and not has_none_ts:
                conflict.resolution = "same_version"
            else:
                # Check if overlay (V650) supersedes foundation (V630/V620)
                has_v650 = 'V650' in v_codes
                has_v630 = 'V630' in v_codes or 'V620' in v_codes

                if has_v650 and has_v630:
                    # Normal: overlay supersedes foundation
                    max_ts = max(timestamps)
                    v650_ts = [e[1] for e in unique_entries
                               if e[3] == 'V650' and e[1]]
                    if v650_ts and max(v650_ts) == max_ts:
                        conflict.resolution = "overlay_supersedes"
                    else:
                        conflict.resolution = "conflict"
                elif has_none_ts:
                    # One side has no timestamp (V620) -- assume newer
                    # V630/V650 supersedes the older V620
                    conflict.resolution = "overlay_supersedes"
                elif len(set(v_codes)) == 1:
                    # Same v-code, different timestamps -- newer wins
                    conflict.resolution = "newer_supersedes"
                else:
                    conflict.resolution = "conflict"

            conflicts.append(conflict)

        return conflicts

    def find_prerequisite_gaps(self, cds: list) -> list:
        """Find subsystems referenced in dependencies but not available."""
        # Collect all available subsystem names
        available = {}  # subsystem_name -> cd_name
        for cd in cds:
            for product in cd.products:
                for sub in product.subsystem_names:
                    available[sub] = cd.name

        # Collect all referenced subsystems from dependency expressions
        all_refs = defaultdict(list)
        for cd in cds:
            for product in cd.products:
                for ref in product.dep_references:
                    all_refs[ref].append(product.spec_filename)

        # Find gaps (referenced but not available)
        gaps = []
        for ref, sources in sorted(all_refs.items()):
            if ref not in available:
                gaps.append(PrerequisiteGap(
                    required_subsystem=ref,
                    required_by=sorted(set(sources)),
                ))

        return gaps

    def check_family_compatibility(self, cds: list) -> list:
        """Check that all CDs belong to compatible version families."""
        mismatches = []

        # Group CDs by type (overlay, foundation, applications)
        overlay_cds = [cd for cd in cds if 'overlay' in cd.version_family]
        foundation_cds = [cd for cd in cds if 'foundation' in cd.version_family]

        # Check overlay CDs are all from the same release
        if len(overlay_cds) > 1:
            families = set(cd.version_family for cd in overlay_cds)
            if len(families) > 1:
                dominant = max(families,
                               key=lambda f: sum(1 for c in overlay_cds
                                                 if c.version_family == f))
                for cd in overlay_cds:
                    if cd.version_family != dominant:
                        mismatches.append(FamilyMismatch(
                            cd_name=cd.name,
                            cd_family=cd.version_family,
                            expected_family=dominant,
                            severity="error",
                            detail=f"Overlay {cd.name} is {cd.version_family}, "
                                   f"expected {dominant}",
                        ))

        # Check foundation timestamps < overlay timestamps
        if foundation_cds and overlay_cds:
            f_ts = [cd.median_timestamp for cd in foundation_cds
                    if cd.median_timestamp]
            o_ts = [cd.median_timestamp for cd in overlay_cds
                    if cd.median_timestamp]

            if f_ts and o_ts and max(f_ts) > max(o_ts):
                mismatches.append(FamilyMismatch(
                    cd_name=foundation_cds[0].name,
                    cd_family=foundation_cds[0].version_family,
                    expected_family="older-than-overlays",
                    severity="error",
                    detail="Foundation timestamp is newer than overlay "
                           "timestamp -- CDs may be mismatched",
                ))

        # Check for wildly different timestamps among overlay CDs
        if len(overlay_cds) > 1:
            o_timestamps = [cd.median_timestamp for cd in overlay_cds
                            if cd.median_timestamp]
            if o_timestamps:
                ts_range = max(o_timestamps) - min(o_timestamps)
                if ts_range > 60 * 86400:  # 60 days
                    mismatches.append(FamilyMismatch(
                        cd_name="(overlay set)",
                        cd_family="mixed",
                        expected_family="consistent",
                        severity="warning",
                        detail=f"Overlay timestamps span "
                               f"{ts_range // 86400} days",
                    ))

        return mismatches


# ── Library Searcher ─────────────────────────────────────────────

class LibrarySearcher:
    """Searches the software library for CDs matching version requirements."""

    def __init__(self, library_root: Path = EXTRACT_BASE):
        self.library_root = library_root
        self._index = None

    def index_library(self) -> dict:
        """Build index: product_name -> [(cd_dir_name, version_ts, spec_filename)]."""
        if self._index is not None:
            return self._index

        self._index = defaultdict(list)
        scanner = CDScanner()

        if not self.library_root.exists():
            return self._index

        for entry in sorted(self.library_root.iterdir()):
            if not entry.is_dir():
                continue

            # Collect directories to scan: try dist/ subdir, flat dir,
            # and also nested subdirectories (e.g., "Irix 6.5.30/Overlays2/dist/")
            targets = []
            dist_dir = entry / "dist"
            if dist_dir.is_dir():
                targets.append((entry.name, dist_dir))
            else:
                targets.append((entry.name, entry))

            # Check for nested subdirectories with dist/ dirs
            try:
                for sub in sorted(entry.iterdir()):
                    if not sub.is_dir() or sub.name == 'dist':
                        continue
                    sub_dist = sub / "dist"
                    if sub_dist.is_dir():
                        targets.append(
                            (f"{entry.name}/{sub.name}", sub_dist))
            except PermissionError:
                pass

            for label, target in targets:
                cd = scanner.scan_directory(target, name=label)
                for product in cd.products:
                    self._index[product.product_name].append(
                        (label, product.version_ts,
                         product.spec_filename, product.description))

        return self._index

    def search_for_product(self, product_name: str,
                            min_version: int = 0) -> list:
        """Find CDs containing this product with version >= min_version."""
        index = self.index_library()
        results = []
        for cd_name, ts, spec, desc in index.get(product_name, []):
            if ts is None or ts >= min_version:
                results.append((cd_name, ts, spec, desc))
        results.sort(key=lambda x: x[1] or 0, reverse=True)
        return results

    def suggest_replacement(self, conflict: VersionConflict) -> Optional[str]:
        """Given a conflict, suggest which CD to swap."""
        # Find the entry with the highest timestamp
        best_ts = max((e[1] for e in conflict.entries if e[1]), default=0)
        if not best_ts:
            return None

        results = self.search_for_product(
            conflict.product_name, min_version=best_ts)
        if results:
            return (f"Library has {conflict.product_name} on: "
                    + ", ".join(f"{r[0]} (ts={r[1]})" for r in results[:3]))
        return None


# ── Product Family System ────────────────────────────────────────

PLATFORMS = {
    "indy":         {"name": "Indy (IP24)",            "max_overlay": "6.5.22"},
    "indigo2":      {"name": "Indigo2 (IP22)",         "max_overlay": "6.5.22"},
    "indigo2-r10k": {"name": "Indigo2 R10K (IP28)",    "max_overlay": "6.5.30"},
    "o2":           {"name": "O2 (IP32)",              "max_overlay": "6.5.30"},
    "octane":       {"name": "Octane (IP30)",          "max_overlay": "6.5.30"},
    "origin":       {"name": "Origin (IP27)",          "max_overlay": "6.5.30"},
}

IRIX_VCODE_COMPAT = {
    "6.5": ["V650", "V630", "V620", "V530"],
    "6.2": ["V620", "V610", "V530"],
    "5.3": ["V530", "V512", "V511", "V500"],
}

# Rank V-codes for sorting: higher index = newer/preferred
_VCODE_RANK = {"V400": 0, "V405": 1, "V500": 2, "V511": 3, "V512": 4,
               "V530": 5, "V610": 6, "V620": 7, "V630": 8, "V650": 9}

_OVERLAY_VERSION_RE = re.compile(r'6\.5\.(\d+)')


def extract_overlay_version(filename):
    """Extract '6.5.22' or '6.5.30' from image filename.

    Returns None if no overlay version found (foundation/app CDs).
    """
    m = _OVERLAY_VERSION_RE.search(filename)
    if m:
        return "6.5.%s" % m.group(1)
    return None


def _overlay_le(a, b):
    """Compare overlay versions: '6.5.22' <= '6.5.30'."""
    try:
        return int(a.split('.')[-1]) <= int(b.split('.')[-1])
    except (ValueError, IndexError):
        return True


@dataclass
class ProductFamily:
    key: str                            # CLI name: "c", "c++", "mipspro"
    name: str                           # Display: "MIPSpro C Compiler"
    product_patterns: list              # Exact product_name matches from DB
    implicit_deps: list                 # Family keys always pulled in
    category: str = ""                  # "compiler", "tools", "library", etc.
    description: str = ""
    base: bool = False                  # Always included (eoe, desktop)


# Registry of known product families
PRODUCT_FAMILIES = {
    # ── Base (always included) ──
    "base_os": ProductFamily(
        key="base_os", name="Base OS",
        product_patterns=["eoe", "license_eoe"],
        implicit_deps=[],
        category="base", base=True,
        description="IRIX execution environment and licensing",
    ),
    "desktop": ProductFamily(
        key="desktop", name="Desktop Environment",
        product_patterns=["x_eoe", "motif_eoe", "desktop_base",
                          "desktop_eoe", "4Dwm", "ViewKit_eoe"],
        implicit_deps=["base_os"],
        category="base", base=True,
        description="X11, Motif, 4Dwm window manager",
    ),
    # ── Compiler support ──
    "dev_headers": ProductFamily(
        key="dev_headers", name="Dev Headers/Libs",
        product_patterns=["dev", "irix_dev", "x_dev", "motif_dev",
                          "gl_dev"],
        implicit_deps=["base_os"],
        category="support",
        description="System headers, X11/Motif/GL development libraries",
    ),
    "compiler_runtime": ProductFamily(
        key="compiler_runtime", name="Compiler Runtime",
        product_patterns=["compiler_dev", "compiler_eoe", "complib",
                          "complib_dev", "complib_eoe"],
        implicit_deps=["dev_headers"],
        category="support",
        description="Shared compiler libraries and runtime support",
    ),
    # ── Languages ──
    "c": ProductFamily(
        key="c", name="MIPSpro C",
        product_patterns=["c_dev", "c_fe"],
        implicit_deps=["compiler_runtime"],
        category="compiler",
        description="MIPSpro C compiler (cc)",
    ),
    "c++": ProductFamily(
        key="c++", name="MIPSpro C++",
        product_patterns=["c++_dev", "c++_fe", "c++_eoe"],
        implicit_deps=["compiler_runtime"],
        category="compiler",
        description="MIPSpro C++ compiler (CC)",
    ),
    "fortran77": ProductFamily(
        key="fortran77", name="Fortran 77",
        product_patterns=["ftn77_dev", "ftn77_fe", "ftn_dev", "ftn_eoe"],
        implicit_deps=["compiler_runtime"],
        category="compiler",
        description="MIPSpro Fortran 77 compiler (f77)",
    ),
    "fortran90": ProductFamily(
        key="fortran90", name="Fortran 90",
        product_patterns=["ftn90_dev", "ftn90_fe"],
        implicit_deps=["compiler_runtime", "fortran77"],
        category="compiler",
        description="MIPSpro Fortran 90 compiler (f90)",
    ),
    "ada": ProductFamily(
        key="ada", name="Ada 95",
        product_patterns=["gnat_dev", "gnat_eoe"],
        implicit_deps=["compiler_runtime"],
        category="compiler",
        description="GNAT Ada 95 compiler",
    ),
    "pascal": ProductFamily(
        key="pascal", name="Pascal",
        product_patterns=["pas", "pas_dev"],
        implicit_deps=["compiler_runtime"],
        category="compiler",
        description="Pascal compiler",
    ),
    "power_c": ProductFamily(
        key="power_c", name="Power C",
        product_patterns=["pwrc", "pwrc_dev"],
        implicit_deps=["c"],
        category="compiler",
        description="Power C auto-parallelizing optimizer",
    ),
    "power_fortran": ProductFamily(
        key="power_fortran", name="Power Fortran",
        product_patterns=["pfa", "pfa_dev", "pf90_dev"],
        implicit_deps=["fortran77"],
        category="compiler",
        description="Power Fortran auto-parallelizing optimizer",
    ),
    # ── Meta ──
    "mipspro": ProductFamily(
        key="mipspro", name="MIPSpro (All)",
        product_patterns=[],
        implicit_deps=["c", "c++", "fortran77", "fortran90"],
        category="meta",
        description="All MIPSpro compilers (C, C++, F77, F90)",
    ),
    # ── Tools ──
    "workshop": ProductFamily(
        key="workshop", name="ProDev WorkShop",
        product_patterns=["WorkShop", "ProDev", "SpeedShop", "dbx"],
        implicit_deps=["compiler_runtime"],
        category="tools",
        description="Debugger, profiler, performance tools",
    ),
    "casevision": ProductFamily(
        key="casevision", name="CASEVision",
        product_patterns=["CaseVision", "CodeVision", "DeltaCC"],
        implicit_deps=["compiler_runtime"],
        category="tools",
        description="Static analysis and code management",
    ),
    "prodev_mpf": ProductFamily(
        key="prodev_mpf", name="WorkShop Pro MPF",
        product_patterns=["WorkShopMPF", "ProMP"],
        implicit_deps=["workshop"],
        category="tools",
        description="Parallel Fortran development tools",
    ),
    # ── Libraries ──
    "imagevision": ProductFamily(
        key="imagevision", name="ImageVision",
        product_patterns=["il", "il_dev", "il_eoe", "ifl_dev", "ifl_eoe"],
        implicit_deps=["dev_headers"],
        category="library",
        description="Image processing library",
    ),
    "performer": ProductFamily(
        key="performer", name="IRIS Performer",
        product_patterns=["performer_dev", "performer_eoe"],
        implicit_deps=["dev_headers"],
        category="library",
        description="Real-time 3D rendering framework",
    ),
    "inventor": ProductFamily(
        key="inventor", name="Open Inventor",
        product_patterns=["inventor_dev", "inventor_eoe"],
        implicit_deps=["dev_headers"],
        category="library",
        description="3D scene graph toolkit",
    ),
    "dmedia": ProductFamily(
        key="dmedia", name="Digital Media",
        product_patterns=["dmedia_dev", "dmedia_eoe", "dmedia_tools"],
        implicit_deps=["dev_headers"],
        category="library",
        description="Audio/video capture and playback",
    ),
    # ── Networking ──
    "nfs": ProductFamily(
        key="nfs", name="NFS/ONC3",
        product_patterns=["nfs", "onc3_eoe"],
        implicit_deps=["base_os"],
        category="networking",
        description="Network File System client and server",
    ),
    "printing": ProductFamily(
        key="printing", name="Printing",
        product_patterns=["print", "impr_base", "impr_rip"],
        implicit_deps=["base_os"],
        category="networking",
        description="Print spooler and Impressario base",
    ),
    # ── System ──
    "insight": ProductFamily(
        key="insight", name="IRIS InSight",
        product_patterns=["insight", "insight_base", "insight_dev"],
        implicit_deps=["base_os"],
        category="system",
        description="Online documentation viewer",
    ),
    "sysadmin": ProductFamily(
        key="sysadmin", name="System Admin",
        product_patterns=["sysadm_base", "sysadmdesktop", "cadmin"],
        implicit_deps=["desktop"],
        category="system",
        description="System administration tools",
    ),
}

# Category display order and labels
FAMILY_CATEGORIES = [
    ("compiler", "Compilers"),
    ("meta",     "Meta Packages"),
    ("support",  "Compiler Support"),
    ("tools",    "Development Tools"),
    ("library",  "Libraries"),
    ("networking", "Networking"),
    ("system",   "System"),
    ("base",     "Base (always included)"),
]


@dataclass
class ResolveResult:
    expanded_families: list         # Family keys after dep expansion
    required_products: set          # Product names needed
    selected_images: list           # [(md5_hash, filename, [products_covered])]
    unresolved_products: list       # Products with no compatible image
    total_size: int = 0             # Sum of image file sizes
    warnings: list = field(default_factory=list)


class FamilyResolver:
    """Resolves product family selections to a minimal set of CD images."""

    def __init__(self, db, target_version="6.5", platform="indy"):
        if platform not in PLATFORMS:
            raise ValueError("Unknown platform %r. Known: %s"
                             % (platform, ", ".join(sorted(PLATFORMS))))
        if target_version not in IRIX_VCODE_COMPAT:
            raise ValueError("Unknown target version %r. Known: %s"
                             % (target_version,
                                ", ".join(sorted(IRIX_VCODE_COMPAT))))
        self.db = db
        self.target = target_version
        self.platform = platform
        self.max_overlay = PLATFORMS[platform]["max_overlay"]
        self.compat_vcodes = set(IRIX_VCODE_COMPAT[target_version])

    def resolve(self, family_keys):
        """Resolve family keys to a minimal set of CD images.

        Returns ResolveResult with selected images and any unresolved products.
        """
        warnings = []

        # Step 1: Expand families (follow implicit_deps, add base families)
        expanded = self._expand_families(family_keys, warnings)

        # Step 2: Collect required products
        required = set()
        for key in expanded:
            fam = PRODUCT_FAMILIES.get(key)
            if fam:
                required.update(fam.product_patterns)

        if not required:
            return ResolveResult(
                expanded_families=sorted(expanded),
                required_products=required,
                selected_images=[],
                unresolved_products=[],
                warnings=warnings,
            )

        # Step 3: Find candidate images for each product
        product_candidates = self._find_candidates(required, warnings)

        # Step 4: Select best version per product
        product_best = {}
        for prod, candidates in product_candidates.items():
            if candidates:
                product_best[prod] = self._rank_best(candidates)

        # Step 5: Greedy set cover — minimize number of images
        selected, unresolved = self._greedy_cover(required, product_best)

        # Step 6: Ensure foundation CDs if overlays are selected
        selected = self._ensure_foundation(selected, warnings)

        # Compute total size
        total_size = 0
        for md5, filename, prods in selected:
            row = self.db.conn.execute(
                "SELECT file_size FROM images WHERE md5_hash = ?", (md5,)
            ).fetchone()
            if row and row[0]:
                total_size += row[0]

        return ResolveResult(
            expanded_families=sorted(expanded),
            required_products=required,
            selected_images=selected,
            unresolved_products=sorted(unresolved),
            total_size=total_size,
            warnings=warnings,
        )

    def _expand_families(self, family_keys, warnings):
        """Recursively expand family dependencies and add base families."""
        expanded = set()
        stack = list(family_keys)

        # Always include base families
        for key, fam in PRODUCT_FAMILIES.items():
            if fam.base:
                stack.append(key)

        while stack:
            key = stack.pop()
            if key in expanded:
                continue
            fam = PRODUCT_FAMILIES.get(key)
            if fam is None:
                warnings.append("Unknown family: %r" % key)
                continue
            expanded.add(key)
            for dep in fam.implicit_deps:
                if dep not in expanded:
                    stack.append(dep)

        return expanded

    def _find_candidates(self, required_products, warnings):
        """Find candidate images for each required product.

        Filters by V-code compatibility and overlay version.
        Returns {product_name: [(md5, filename, vcode, version_ts)]}.
        """
        result = defaultdict(list)
        for prod in required_products:
            rows = self.db.conn.execute(
                "SELECT p.v_code, p.version_ts, i.md5_hash, i.filename "
                "FROM products p JOIN images i ON p.image_hash = i.md5_hash "
                "WHERE p.product_name = ?", (prod,)
            ).fetchall()

            seen = set()  # Deduplicate by (md5, prod)
            for vcode, vts, md5, filename in rows:
                if (md5, prod) in seen:
                    continue
                seen.add((md5, prod))

                # Filter: V-code must be compatible
                if vcode and vcode not in self.compat_vcodes:
                    continue

                # Filter: overlay version must be <= platform max
                ov = extract_overlay_version(filename)
                if ov and not _overlay_le(ov, self.max_overlay):
                    continue

                # Filter: skip combined_dist images
                if 'combined_dist' in filename.lower():
                    continue

                result[prod].append((md5, filename, vcode or "", vts))

        return result

    def _rank_best(self, candidates):
        """Rank candidates and return sorted best-first.

        Prefers: higher V-code rank, then higher version_ts.
        """
        def score(c):
            md5, filename, vcode, vts = c
            return (_VCODE_RANK.get(vcode, -1), vts or 0)
        return sorted(candidates, key=score, reverse=True)

    def _greedy_cover(self, required, product_best):
        """Greedy set cover to minimize number of CD images.

        Returns (selected_images, unresolved_products).
        """
        uncovered = set(required)
        selected = []  # [(md5, filename, [products_covered])]
        selected_hashes = set()

        # Remove products with no candidates
        unresolved = set()
        for prod in list(uncovered):
            if prod not in product_best or not product_best[prod]:
                unresolved.add(prod)
                uncovered.discard(prod)

        while uncovered:
            # For each candidate image, count how many uncovered products
            # it provides (using the best candidate for each product)
            image_covers = defaultdict(set)
            for prod in uncovered:
                for md5, filename, vcode, vts in product_best.get(prod, []):
                    image_covers[(md5, filename)].add(prod)

            if not image_covers:
                # Remaining products can't be covered
                unresolved.update(uncovered)
                break

            # Pick image covering the most uncovered products
            best_key = max(image_covers, key=lambda k: len(image_covers[k]))
            covered = image_covers[best_key]
            md5, filename = best_key

            selected.append((md5, filename, sorted(covered)))
            selected_hashes.add(md5)
            uncovered -= covered

        return selected, unresolved

    def _ensure_foundation(self, selected, warnings):
        """If overlay images are selected, ensure matching foundation CDs.

        Foundation products (eoe, x_eoe, etc.) are on V630 foundation CDs.
        Overlay CDs supersede some products but foundation CDs provide the
        base system needed for installation.
        """
        has_overlay = False
        selected_hashes = {s[0] for s in selected}
        for md5, filename, prods in selected:
            ov = extract_overlay_version(filename)
            if ov:
                has_overlay = True
                break

        if not has_overlay or self.target != "6.5":
            return selected

        # Check if foundation CDs are already included
        foundation_names = ["IRIX 6.5 Foundation 1",
                            "IRIX 6.5 Foundation 2"]
        has_foundation = set()
        for md5, filename, prods in selected:
            for fn in foundation_names:
                if fn.lower() in filename.lower():
                    has_foundation.add(fn)

        # Add missing foundation CDs
        for fn in foundation_names:
            if fn not in has_foundation:
                rows = self.db.conn.execute(
                    "SELECT md5_hash, filename FROM images "
                    "WHERE filename LIKE ?", ("%" + fn + "%",)
                ).fetchall()
                if rows:
                    # Pick shortest filename (most canonical)
                    rows.sort(key=lambda r: len(r[1]))
                    md5, filename = rows[0]
                    if md5 not in selected_hashes:
                        prods = [r[0] for r in self.db.conn.execute(
                            "SELECT product_name FROM products "
                            "WHERE image_hash = ?", (md5,)
                        )]
                        selected.append((md5, filename,
                                         sorted(set(prods))))
                        selected_hashes.add(md5)
                        warnings.append("Added foundation CD: %s"
                                        % filename)

        return selected

    def list_available_families(self):
        """Cross-reference families with DB to show which have images.

        Returns {family_key: {product: count_of_images}}.
        """
        result = {}
        for key, fam in PRODUCT_FAMILIES.items():
            prod_counts = {}
            for prod in fam.product_patterns:
                rows = self.db.conn.execute(
                    "SELECT COUNT(DISTINCT i.md5_hash) "
                    "FROM products p JOIN images i "
                    "ON p.image_hash = i.md5_hash "
                    "WHERE p.product_name = ?", (prod,)
                ).fetchone()
                count = rows[0] if rows else 0
                # Also check compatibility
                compat_rows = self.db.conn.execute(
                    "SELECT COUNT(DISTINCT i.md5_hash) "
                    "FROM products p JOIN images i "
                    "ON p.image_hash = i.md5_hash "
                    "WHERE p.product_name = ? AND p.v_code IN (%s)"
                    % ",".join("?" for _ in self.compat_vcodes),
                    (prod, *self.compat_vcodes)
                ).fetchone()
                compat = compat_rows[0] if compat_rows else 0
                prod_counts[prod] = {"total": count, "compatible": compat}
            result[key] = prod_counts
        return result


# ── Helpers ──────────────────────────────────────────────────────

def _resolve_dist_dirs(config_name: str = None,
                        cd_paths: list = None) -> list:
    """Resolve CD dist directories from config name or explicit paths.

    Returns list of (name, Path) tuples.
    """
    if cd_paths:
        result = []
        for p in cd_paths:
            path = Path(p)
            if not path.exists():
                print(f"WARNING: {p} does not exist", file=sys.stderr)
                continue
            dist = path / "dist"
            target = dist if dist.is_dir() else path
            result.append((path.name, target))
        return result

    if config_name:
        # Import CONFIGS from combine_dist.py
        try:
            from pyirix.dist.combine import CONFIGS, find_dist_dirs
            if config_name not in CONFIGS:
                print(f"Unknown config: {config_name!r}. "
                      f"Available: {', '.join(CONFIGS)}",
                      file=sys.stderr)
                return []
            return find_dist_dirs(CONFIGS[config_name])
        except ImportError:
            print("Could not import combine_dist.py", file=sys.stderr)
            return []

    # Default: scan EXTRACT_BASE for standard 6.5 CDs
    from pyirix.dist.combine import CONFIGS, find_dist_dirs
    return find_dist_dirs(CONFIGS.get("6.5", {}))


def _resolve_cds(args) -> list:
    """Resolve CDInfo objects from CLI args (config, dirs, or images).

    Supports three input sources:
      --config NAME   Load CD list from combine_dist.py config
      --cds DIR ...   Scan extracted dist directories
      --images FILE...  Read spec files from EFS disk images

    Multiple sources can be combined. Returns list of CDInfo.
    """
    cds = []

    # Source 1: extracted directories (--cds or --config)
    image_paths = getattr(args, 'images', None)
    cd_paths = getattr(args, 'cds', None)
    config_name = getattr(args, 'config', None)

    dist_dirs = _resolve_dist_dirs(config_name, cd_paths)
    if dist_dirs:
        scanner = CDScanner()
        for name, d in dist_dirs:
            cds.append(scanner.scan_directory(Path(d), name=name))

    # Source 2: EFS disk images (--images) — use DB-backed scanning
    if image_paths:
        db = PackageDatabase()
        try:
            for p in image_paths:
                path = Path(p)
                if not path.exists():
                    print(f"WARNING: {p} does not exist", file=sys.stderr)
                    continue
                cd = db.scan_or_lookup(path)
                if cd:
                    cds.append(cd)
        finally:
            db.close()

    return cds


def _ts_str(ts: Optional[int]) -> str:
    """Format a Unix timestamp as a date string."""
    if ts is None:
        return "N/A"
    return time.strftime('%Y-%m-%d', time.gmtime(ts))


# ── CLI Commands ─────────────────────────────────────────────────

def cmd_analyze(args):
    """Full analysis: versions, conflicts, family compatibility."""
    cds = _resolve_cds(args)
    if not cds:
        print("No CDs found. Use --config, --cds, or --images.",
              file=sys.stderr)
        return 1

    print("IRIX Package Conflict Analysis")
    print("=" * 60)

    # CD summary
    print(f"\nCD Collection ({len(cds)} CDs):")
    for cd in cds:
        ts_str = _ts_str(cd.median_timestamp)
        print(f"  {cd.name:45s} {cd.products[0].v_code if cd.products else '?':4s}  "
              f"{len(cd.products):3d} products  {ts_str}")

    # Version families
    print(f"\nVersion Families:")
    families = defaultdict(list)
    for cd in cds:
        families[cd.version_family].append(cd)
    for family, family_cds in sorted(families.items()):
        timestamps = [c.median_timestamp for c in family_cds
                      if c.median_timestamp]
        ts_str = _ts_str(timestamps[0] if timestamps else None)
        print(f"  {family:25s} ({len(family_cds)} CDs): {ts_str}")

    # Run analysis
    analyzer = ConflictAnalyzer()
    report = analyzer.analyze(cds)

    # Family mismatches
    if report.family_mismatches:
        print(f"\nFamily Mismatches ({len(report.family_mismatches)}):")
        for m in report.family_mismatches:
            icon = "ERROR" if m.severity == "error" else "WARN"
            print(f"  [{icon}] {m.detail}")
    else:
        all_ts = [cd.median_timestamp for cd in cds if cd.median_timestamp]
        if all_ts and len(all_ts) > 1:
            span = max(all_ts) - min(all_ts)
            print(f"\n  Compatible: YES (timestamp span: {span // 86400} days)")

    # Version conflicts
    real_conflicts = [c for c in report.version_conflicts
                      if c.resolution == "conflict"]
    ok_conflicts = [c for c in report.version_conflicts
                    if c.resolution != "conflict"]

    print(f"\nVersion Overlaps ({len(report.version_conflicts)} products "
          f"on multiple CDs):")
    for c in report.version_conflicts:
        entries_str = " -> ".join(
            f"{e[0]} {e[1] or '?'}" for e in c.entries)
        if c.resolution in ("overlay_supersedes", "newer_supersedes"):
            status = "OK (superseded)"
        elif c.resolution == "same_version":
            status = "OK (same)"
        elif c.resolution == "conflict":
            status = "CONFLICT"
        else:
            status = c.resolution
        print(f"  {c.product_name:25s} {entries_str}  {status}")

    # Prerequisite gaps
    if report.prerequisite_gaps:
        shown = report.prerequisite_gaps[:20]
        print(f"\nPrerequisite Gaps ({len(report.prerequisite_gaps)}, "
              f"showing {len(shown)}):")
        for gap in shown:
            by_str = ", ".join(gap.required_by[:3])
            if len(gap.required_by) > 3:
                by_str += f" +{len(gap.required_by) - 3} more"
            print(f"  {gap.required_subsystem:40s}  <- {by_str}")

    # Recommendations
    print(f"\nRecommendations:")
    for rec in report.recommendations:
        print(f"  - {rec}")

    # Result
    result = "SAFE TO COMBINE" if report.safe_to_combine else "CONFLICTS FOUND"
    print(f"\nResult: {result}")
    if real_conflicts:
        print(f"  {len(real_conflicts)} product(s) have version conflicts")

    return 0 if report.safe_to_combine else 1


def cmd_versions(args):
    """Table of all products across all CDs with version timestamps."""
    cds = _resolve_cds(args)
    if not cds:
        print("No CDs found. Use --config, --cds, or --images.",
              file=sys.stderr)
        return 1

    # Collect all products
    all_products = []
    for cd in cds:
        for p in cd.products:
            all_products.append(p)

    all_products.sort(key=lambda p: (p.product_name, p.version_ts or 0))

    print(f"{'Product':25s} {'Spec File':30s} {'V':4s} {'Timestamp':12s} "
          f"{'Date':12s} {'CD':s}")
    print("-" * 110)
    for p in all_products:
        print(f"{p.product_name:25s} {p.spec_filename:30s} {p.v_code:4s} "
              f"{str(p.version_ts or ''):12s} {_ts_str(p.version_ts):12s} "
              f"{p.cd_source}")

    print(f"\nTotal: {len(all_products)} products across {len(cds)} CDs")
    return 0


def cmd_conflicts(args):
    """Show only conflicts (concise output)."""
    cds = _resolve_cds(args)
    if not cds:
        print("No CDs found. Use --config, --cds, or --images.",
              file=sys.stderr)
        return 1

    analyzer = ConflictAnalyzer()
    report = analyzer.analyze(cds)

    real = [c for c in report.version_conflicts
            if c.resolution == "conflict"]

    if not real:
        print("No version conflicts found.")
        return 0

    print(f"{len(real)} version conflict(s):")
    for c in real:
        for cd_name, ts, spec in c.entries:
            print(f"  {c.product_name:25s} {spec:30s} ts={ts or '?':>12s}  {cd_name}")
        print()

    return 1


def cmd_search(args):
    """Search the full software library for a product."""
    searcher = LibrarySearcher()
    results = searcher.search_for_product(
        args.product,
        min_version=args.min_version or 0)

    if not results:
        print(f"Product '{args.product}' not found in library.")
        # Try fuzzy match
        index = searcher.index_library()
        matches = [name for name in index
                   if args.product.lower() in name.lower()]
        if matches:
            print(f"Similar products: {', '.join(matches[:10])}")
        return 1

    print(f"Product '{args.product}' found on {len(results)} CD(s):")
    print(f"{'CD':45s} {'Timestamp':12s} {'Date':12s} {'Spec File':s}")
    print("-" * 100)
    for cd_name, ts, spec, desc in results:
        print(f"{cd_name:45s} {str(ts or ''):12s} {_ts_str(ts):12s} {spec}")
    if results and results[0][3]:
        print(f"\nDescription: {results[0][3]}")

    return 0


def cmd_validate_config(args):
    """Validate a combine_dist.py configuration."""
    config_name = args.config_name

    dist_dirs = _resolve_dist_dirs(config_name)
    if not dist_dirs:
        print(f"No dist directories found for config '{config_name}'.",
              file=sys.stderr)
        return 1

    scanner = CDScanner()
    cds = [scanner.scan_directory(Path(d), name=name)
           for name, d in dist_dirs]

    analyzer = ConflictAnalyzer()
    report = analyzer.analyze(cds)

    print(f"Config '{config_name}': {len(cds)} CDs, "
          f"{sum(len(cd.products) for cd in cds)} products")
    report.print_summary()

    if report.safe_to_combine:
        print(f"\nValidation PASSED for config '{config_name}'")
        return 0
    else:
        print(f"\nValidation FAILED for config '{config_name}'")
        return 1


def cmd_scan_image(args):
    """Scan one or more EFS images and display product metadata."""
    db = PackageDatabase()

    try:
        for image_path in args.images:
            path = Path(image_path)
            if not path.exists():
                print(f"ERROR: {image_path} does not exist", file=sys.stderr)
                continue

            md5 = db.compute_hash(path)
            was_cached = db.lookup(md5) is not None
            print(f"Scanning: {path.name}"
                  f"{' (cached)' if was_cached else ''}")
            cd = db.scan_or_lookup(path)
            if cd is None:
                print(f"  Failed to read EFS image\n")
                continue

            print(f"  MD5: {md5}")
            print(f"  Family: {cd.version_family}")
            print(f"  Median timestamp: {_ts_str(cd.median_timestamp)}")
            print(f"  Products ({len(cd.products)}):")
            print(f"  {'Product':25s} {'Spec File':30s} {'V':4s} "
                  f"{'Timestamp':12s} {'Date':12s}")
            print(f"  {'-'*90}")
            for p in sorted(cd.products,
                            key=lambda x: (x.product_name,
                                           x.version_ts or 0)):
                print(f"  {p.product_name:25s} {p.spec_filename:30s} "
                      f"{p.v_code:4s} {str(p.version_ts or ''):12s} "
                      f"{_ts_str(p.version_ts):12s}")
                if p.subsystem_names:
                    print(f"    subsystems: "
                          f"{', '.join(p.subsystem_names[:5])}"
                          f"{'...' if len(p.subsystem_names) > 5 else ''}")
            print()
    finally:
        db.close()

    return 0


def cmd_db(args):
    """Manage the package scan database."""
    if args.drop:
        db_path = PackageDatabase.DEFAULT_PATH
        if db_path.exists():
            db_path.unlink()
            print(f"Deleted {db_path}")
        else:
            print(f"No database at {db_path}")
        return 0

    db = PackageDatabase()
    try:
        if args.scan_all:
            sw_lib = PROJECT_ROOT / "software_library"
            img_files = sorted(
                p for p in sw_lib.rglob("*.img")
                if not p.name.startswith('.')
            )
            if not img_files:
                print(f"No .img files found under {sw_lib}")
                return 1

            new = cached = failed = 0
            for p in img_files:
                md5 = db.compute_hash(p)
                if db.lookup(md5) is not None:
                    cached += 1
                    continue
                scanner = EFSImageScanner()
                cd = scanner.scan_image(p)
                if cd:
                    db.store(md5, p.name, p.stat().st_size, cd)
                    new += 1
                    print(f"  + {p.name} ({len(cd.products)} products)")
                else:
                    failed += 1

            print(f"\nScan complete: {new} new, {cached} cached, "
                  f"{failed} failed")
            return 0

        if args.detail:
            prefix = args.detail
            full_hash = db.find_by_hash_prefix(prefix)
            if not full_hash:
                print(f"No image found matching hash prefix '{prefix}'")
                return 1

            images = db.list_images()
            img = next(i for i in images if i['md5_hash'] == full_hash)
            print(f"Image: {img['filename']}")
            print(f"  Hash: {full_hash}")
            print(f"  Size: {img['file_size']:,} bytes")
            print(f"  Family: {img['version_family']}")
            print(f"  Scanned: {img['scan_date']}")
            print(f"  Median timestamp: "
                  f"{_ts_str(img['median_timestamp'])}")
            print()

            products = db.get_image_products(full_hash)
            print(f"  Products ({len(products)}):")
            print(f"  {'Product':25s} {'Spec File':30s} {'V':4s} "
                  f"{'Timestamp':12s} {'Date':12s}")
            print(f"  {'-'*90}")
            for p in products:
                print(f"  {p['product_name']:25s} "
                      f"{p['spec_filename']:30s} "
                      f"{p['v_code'] or '?':4s} "
                      f"{str(p['version_ts'] or ''):12s} "
                      f"{_ts_str(p['version_ts']):12s}")
            return 0

        # Default: list all images
        images = db.list_images()
        if not images:
            print("Database is empty. Use 'db --scan-all' or "
                  "'scan-image' to populate.")
            return 0

        print(f"{'Hash':10s} {'Filename':45s} {'Family':22s} "
              f"{'Products':>8s} {'Scanned':s}")
        print("-" * 100)
        for img in images:
            print(f"{img['md5_hash'][:8]:10s} "
                  f"{img['filename']:45s} "
                  f"{(img['version_family'] or '?'):22s} "
                  f"{img['product_count']:>8d} "
                  f"{img['scan_date'][:10]:s}")
        print(f"\n{len(images)} image(s) in database")
        return 0
    finally:
        db.close()


def cmd_compat(args):
    """Check compatibility across a set of CD images using the database."""
    db = PackageDatabase()
    try:
        cds = []
        hashes = []
        for image_path in args.images:
            path = Path(image_path)
            if not path.exists():
                print(f"ERROR: {image_path} does not exist", file=sys.stderr)
                continue
            md5 = db.compute_hash(path)
            cd = db.scan_or_lookup(path)
            if cd:
                cds.append(cd)
                hashes.append(md5)

        if len(cds) < 2:
            print("Need at least 2 images for compatibility check.",
                  file=sys.stderr)
            return 1

        # Print image set
        print(f"Image Set ({len(cds)} images):")
        for md5, cd in zip(hashes, cds):
            print(f"  {md5[:8]}  {cd.name:45s} "
                  f"{cd.version_family:22s} "
                  f"{len(cd.products):3d} products")

        # Run analysis
        analyzer = ConflictAnalyzer()
        report = analyzer.analyze(cds)

        # Version overlaps summary
        overlaps = report.version_conflicts
        if overlaps:
            real_conflicts = [c for c in overlaps
                              if c.resolution == "conflict"]
            ok = [c for c in overlaps if c.resolution != "conflict"]
            print(f"\nVersion Overlaps ({len(overlaps)} products):"
                  f" {len(ok)} OK"
                  f"{f', {len(real_conflicts)} CONFLICT' if real_conflicts else ''}")
            for c in overlaps:
                entries_str = " -> ".join(
                    f"{e[0]} {e[1] or '?'}" for e in c.entries)
                if c.resolution in ("overlay_supersedes",
                                     "newer_supersedes"):
                    status = "OK (superseded)"
                elif c.resolution == "same_version":
                    status = "OK (same)"
                elif c.resolution == "conflict":
                    status = "CONFLICT"
                else:
                    status = c.resolution
                print(f"  {c.product_name:25s} {status}")

        # Family mismatches
        if report.family_mismatches:
            print(f"\nFamily Issues ({len(report.family_mismatches)}):")
            for m in report.family_mismatches:
                icon = "ERROR" if m.severity == "error" else "WARN"
                print(f"  [{icon}] {m.detail}")

        # Result
        result = "COMPATIBLE" if report.safe_to_combine else "CONFLICTS"
        print(f"\nResult: {result}")
        return 0 if report.safe_to_combine else 1
    finally:
        db.close()


def cmd_families(args):
    """List available product families, optionally cross-referenced with DB."""
    show_available = getattr(args, 'available', False)
    platform = getattr(args, 'platform', 'indy')

    availability = {}
    if show_available:
        db = PackageDatabase()
        try:
            resolver = FamilyResolver(db, platform=platform)
            availability = resolver.list_available_families()
        finally:
            db.close()

    print("Product Families")
    print("=" * 60)

    for cat_key, cat_label in FAMILY_CATEGORIES:
        families_in_cat = [(k, f) for k, f in PRODUCT_FAMILIES.items()
                           if f.category == cat_key]
        if not families_in_cat:
            continue

        print("\n  %s:" % cat_label)
        for key, fam in families_in_cat:
            deps_str = ""
            if fam.implicit_deps:
                deps_str = "  depends: %s" % ", ".join(fam.implicit_deps)
            if not fam.product_patterns and fam.implicit_deps:
                deps_str = "  meta: %s" % " + ".join(fam.implicit_deps)

            line = "    %-16s %-24s%s" % (key, fam.name, deps_str)

            if show_available and key in availability:
                avail = availability[key]
                if not fam.product_patterns:
                    line += "  (meta)"
                else:
                    total_compat = sum(
                        1 for p in avail.values() if p["compatible"] > 0)
                    line += "  [%d/%d available]" % (
                        total_compat, len(fam.product_patterns))

            print(line)

    print()
    if show_available:
        print("Availability checked for: IRIX 6.5, %s"
              % PLATFORMS[platform]["name"])

    return 0


def cmd_resolve(args):
    """Resolve product families to a minimal set of CD images."""
    family_keys = args.families
    platform = getattr(args, 'platform', 'indy')
    target = getattr(args, 'target', '6.5')

    db = PackageDatabase()
    try:
        resolver = FamilyResolver(db, target_version=target,
                                  platform=platform)
        result = resolver.resolve(family_keys)
    finally:
        db.close()

    plat = PLATFORMS[platform]
    print("Target: IRIX %s, %s, max overlay: %s"
          % (target, plat["name"], plat["max_overlay"]))
    print()

    # Show expanded families
    user_fams = [k for k in result.expanded_families
                 if k in family_keys]
    auto_fams = [k for k in result.expanded_families
                 if k not in family_keys]
    print("Families: %s" % ", ".join(user_fams), end="")
    if auto_fams:
        print(" (+ %s)" % ", ".join(auto_fams))
    else:
        print()
    print()

    # Show required products
    print("Required products (%d): %s"
          % (len(result.required_products),
             ", ".join(sorted(result.required_products))))
    print()

    # Show selected images
    if result.selected_images:
        print("Required CD Images (%d):" % len(result.selected_images))
        for md5, filename, prods in result.selected_images:
            ov = extract_overlay_version(filename)
            tag = " (overlay)" if ov else ""
            print("  %s  %-55s %2d products%s"
                  % (md5[:8], filename, len(prods), tag))
    else:
        print("No CD images needed.")

    # Show unresolved
    if result.unresolved_products:
        print()
        print("UNRESOLVED (%d): %s"
              % (len(result.unresolved_products),
                 ", ".join(result.unresolved_products)))

    # Show warnings
    if result.warnings:
        print()
        for w in result.warnings:
            print("  WARNING: %s" % w)

    # Summary
    if result.total_size:
        size_mb = result.total_size / (1024 * 1024)
        print("\nTotal: %d images, %.0f MB" % (
            len(result.selected_images), size_mb))
    else:
        print("\nTotal: %d images" % len(result.selected_images))

    return 1 if result.unresolved_products else 0


def cmd_build_dist(args):
    """Build a combined distribution image from resolved families.

    Resolves families via FamilyResolver, locates source EFS images on disk,
    extracts dist/ files from each, deduplicates (later images take priority),
    and builds a combined EFS disk image ready for IRIX inst.
    """
    import tempfile
    import shutil
    from pyirix.dist.combine import (extract_dist_from_image, collect_dist_files,
                              EFSImageBuilder, build_volume_header,
                              EFS_PARTITION_START, EFS_BLOCK_SIZE,
                              SECTOR_SIZE, VH_SIZE, S_IFREG, S_IFLNK)

    family_keys = args.families
    platform = getattr(args, 'platform', 'indy')
    target = getattr(args, 'target', '6.5')
    output = getattr(args, 'output', None)

    if not output:
        print("ERROR: --output path required", file=sys.stderr)
        return 1

    output = str(Path(output).resolve())

    # Step 1: Resolve families to images
    print("Resolving families: %s" % ", ".join(family_keys))
    db = PackageDatabase()
    try:
        resolver = FamilyResolver(db, target_version=target,
                                  platform=platform)
        result = resolver.resolve(family_keys)
    finally:
        db.close()

    if result.unresolved_products:
        print("WARNING: %d unresolved products: %s"
              % (len(result.unresolved_products),
                 ", ".join(result.unresolved_products)))

    if not result.selected_images:
        print("No images to combine.", file=sys.stderr)
        return 1

    # Step 2: Find image files on disk
    sw_lib = PROJECT_ROOT / "software_library"
    image_paths = []
    for md5, filename, prods in result.selected_images:
        found = list(sw_lib.rglob(filename))
        if not found:
            found = [p for p in sw_lib.rglob("*.img")
                     if p.name == filename]
        if found:
            image_paths.append((found[0], prods))
            print("  Found: %s (%d products)" % (found[0].name, len(prods)))
        else:
            print("  NOT FOUND: %s" % filename, file=sys.stderr)
            return 1

    print("\nResolved %d images" % len(image_paths))

    # Step 3: Extract dist/ files from each image to temp dirs
    # Order: process in resolved order (FamilyResolver already orders them)
    temp_base = tempfile.mkdtemp(prefix="irix_build_dist_")
    temp_dirs = []  # [(label, Path)]

    try:
        for i, (img_path, prods) in enumerate(image_paths):
            label = img_path.stem[:40]
            temp_dir = os.path.join(temp_base, "%02d_%s" % (i, label))
            print("\nExtracting: %s" % img_path.name)
            count = extract_dist_from_image(str(img_path), temp_dir)
            print("  Extracted %d files" % count)
            if count > 0:
                temp_dirs.append((label, Path(temp_dir)))

        if not temp_dirs:
            print("ERROR: No files extracted from any image",
                  file=sys.stderr)
            return 1

        # Step 4: Collect and deduplicate (later dirs take priority)
        print("\nCollecting and deduplicating files...")
        files, total_size, conflicts = collect_dist_files(temp_dirs)
        print("  Total unique files: %d" % len(files))
        print("  Total size: %dMB" % (total_size // (1024 * 1024)))
        if conflicts:
            print("  Dedup overlaps: %d (later images took priority)"
                  % len(conflicts))

        # Step 5: Build combined EFS image
        efs_bytes = int(total_size * 1.2) + 64 * 1024 * 1024
        efs_blocks = efs_bytes // EFS_BLOCK_SIZE
        total_sectors = EFS_PARTITION_START + efs_blocks

        print("\nBuilding EFS filesystem...")
        builder = EFSImageBuilder(efs_blocks)
        builder.add_directory("dist")

        symlink_count = 0
        for i, (rel_path, host_path, is_symlink, link_target) in enumerate(files):
            if is_symlink:
                builder.add_symlink(rel_path, link_target)
                symlink_count += 1
            else:
                with open(host_path, 'rb') as f:
                    data = f.read()
                builder.add_file(rel_path, data)

            if (i + 1) % 50 == 0 or i == len(files) - 1:
                print("\r  Added %d/%d files..." % (i + 1, len(files)),
                      end='', flush=True)
        print()

        # Build EFS to temp file, then prepend volume header
        tmp_efs = os.path.join(temp_base, "efs.tmp")
        builder.build(tmp_efs)

        print("\nBuilding final disk image with volume header...")
        os.makedirs(os.path.dirname(output) or '.', exist_ok=True)

        actual_total = EFS_PARTITION_START + builder.fs_size
        with open(output, 'wb') as out:
            vh = build_volume_header(actual_total, EFS_PARTITION_START)
            out.write(vh)
            pad_bytes = EFS_PARTITION_START * SECTOR_SIZE - VH_SIZE
            out.write(b'\x00' * pad_bytes)
            with open(tmp_efs, 'rb') as efs_in:
                while True:
                    chunk = efs_in.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)

        final_size = os.path.getsize(output)
        print("\nCombined image created: %s" % output)
        print("  Size: %dMB" % (final_size // (1024 * 1024)))
        print("  Files: %d (%d symlinks)" % (len(files), symlink_count))

    finally:
        shutil.rmtree(temp_base, ignore_errors=True)

    return 0


def cmd_simulate(args):
    """Simulate inst 'keep * + install standard' for a target system."""
    target_name = args.target
    verbose = getattr(args, 'verbose', False)
    image_paths = getattr(args, 'image', None) or []
    dist_paths = getattr(args, 'dist', None) or []

    if not image_paths and not dist_paths:
        print("ERROR: specify --image or --dist", file=sys.stderr)
        return 1

    try:
        sim = InstSimulator(target_name, verbose=verbose)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Load sources
    for p in dist_paths:
        path = Path(p)
        if not path.exists():
            print(f"ERROR: {p} does not exist", file=sys.stderr)
            return 1
        print(f"Loading dist: {path.name}")
        sim.load_dist(path)

    for p in image_paths:
        path = Path(p)
        if not path.exists():
            print(f"ERROR: {p} does not exist", file=sys.stderr)
            return 1
        print(f"Loading image: {path.name}")
        sim.load_image(path)

    # Run simulation
    print()
    result = sim.simulate()

    # Print results
    t = result.target
    print(f"Target: {target_name} (CPUBOARD={t.cpuboard}, "
          f"MODE={t.mode}, GFX={t.gfxboard})")
    print(f"Products: {result.total_products}, "
          f"Subsystems: {result.total_subsystems} total, "
          f"{result.selected_subsystems} selected, "
          f"{result.hw_excluded_subsystems} hw-excluded")

    if result.install_size:
        size_mb = result.install_size / (1024 * 1024)
        print(f"Install size for {t.cpuboard}: ~{size_mb:.0f} MB")

    if result.conflicts:
        print(f"\nConflicts ({len(result.conflicts)}):")
        for i, c in enumerate(result.conflicts, 1):
            ctype = c.conflict_type.upper().replace('_', ' ')
            print(f"  {i:3d}. {ctype}: {c.detail}")
            print(f"       -> {c.resolution}")
    else:
        print("\nNo conflicts detected.")

    if verbose:
        # Show hw-excluded subsystems detail
        excluded = [r for r in result.subsystem_records if r.fully_excluded]
        if excluded:
            print(f"\nHW-excluded subsystems ({len(excluded)}):")
            for r in excluded:
                print(f"  {r.name:45s}  "
                      f"{r.total_files:4d} files total, 0 for target")

    return 1 if result.conflicts else 0


# ── Integration hook for combine_dist.py ─────────────────────────

def run_preflight(dist_dirs: list) -> bool:
    """Run pre-flight analysis on dist directories.

    Called from combine_dist.py before building or checking.
    Returns True if safe to combine.
    """
    scanner = CDScanner()
    cds = [scanner.scan_directory(Path(d), name=name)
           for name, d in dist_dirs]

    if not any(cd.products for cd in cds):
        # No spec files parsed -- skip analysis silently
        return True

    analyzer = ConflictAnalyzer()
    report = analyzer.analyze(cds)
    report.print_summary()
    return report.safe_to_combine


# ── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyze IRIX distribution packages for version conflicts"
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Common args for analysis commands
    def add_cd_args(p):
        p.add_argument('--config', '-c',
                        help='Config from combine_dist.py (6.5, 6.5.5, mipspro)')
        p.add_argument('--cds', nargs='+',
                        help='Explicit dist directory paths')
        p.add_argument('--images', nargs='+',
                        help='EFS disk image paths (.img files)')

    # analyze
    p = subparsers.add_parser('analyze', help='Full conflict analysis')
    add_cd_args(p)

    # versions
    p = subparsers.add_parser('versions', help='Version table for all products')
    add_cd_args(p)

    # conflicts
    p = subparsers.add_parser('conflicts', help='Show only conflicts')
    add_cd_args(p)

    # search
    p = subparsers.add_parser('search', help='Search library for a product')
    p.add_argument('product', help='Product name to search for')
    p.add_argument('--min-version', type=int, default=0,
                    help='Minimum version timestamp')

    # validate-config
    p = subparsers.add_parser('validate-config',
                               help='Validate a combine_dist.py config')
    p.add_argument('config_name', help='Config name (6.5, 6.5.5, mipspro)')

    # scan-image
    p = subparsers.add_parser('scan-image',
                               help='Scan EFS disk images for product metadata')
    p.add_argument('images', nargs='+',
                    help='EFS disk image paths')

    # db
    p = subparsers.add_parser('db',
                               help='Manage the package scan database')
    p.add_argument('--detail', metavar='HASH',
                    help='Show products for image by hash prefix')
    p.add_argument('--scan-all', action='store_true',
                    help='Scan all .img files in software_library/')
    p.add_argument('--drop', action='store_true',
                    help='Delete the database file')

    # compat
    p = subparsers.add_parser('compat',
                               help='Check compatibility across CD images')
    p.add_argument('images', nargs='+',
                    help='EFS disk image paths')

    # families
    p = subparsers.add_parser('families',
                               help='List available product families')
    p.add_argument('--available', action='store_true',
                    help='Cross-reference with DB to show image availability')
    p.add_argument('--platform', default='indy',
                    choices=sorted(PLATFORMS.keys()),
                    help='Target platform (default: indy)')

    # resolve
    p = subparsers.add_parser('resolve',
                               help='Resolve product families to CD images')
    p.add_argument('families', nargs='+',
                    help='Family keys (e.g., c c++ workshop)')
    p.add_argument('--platform', default='indy',
                    choices=sorted(PLATFORMS.keys()),
                    help='Target platform (default: indy)')
    p.add_argument('--target', default='6.5',
                    choices=sorted(IRIX_VCODE_COMPAT.keys()),
                    help='Target IRIX version (default: 6.5)')

    # build-dist
    p = subparsers.add_parser('build-dist',
                               help='Resolve families and locate CD images')
    p.add_argument('families', nargs='+',
                    help='Family keys (e.g., c c++ workshop)')
    p.add_argument('--platform', default='indy',
                    choices=sorted(PLATFORMS.keys()),
                    help='Target platform (default: indy)')
    p.add_argument('--target', default='6.5',
                    choices=sorted(IRIX_VCODE_COMPAT.keys()),
                    help='Target IRIX version (default: 6.5)')
    p.add_argument('--output', '-o',
                    help='Output image path')

    # simulate
    p = subparsers.add_parser('simulate',
                               help='Simulate inst keep*/install standard')
    p.add_argument('--target', '-t', default='indy',
                    choices=sorted(TARGET_CONFIGS.keys()),
                    help='Target system (default: indy)')
    p.add_argument('--image', nargs='+',
                    help='EFS disk image paths (.img files)')
    p.add_argument('--dist', nargs='+',
                    help='Extracted dist directory paths')
    p.add_argument('-v', '--verbose', action='store_true',
                    help='Show detailed output')

    args = parser.parse_args()

    commands = {
        'analyze': cmd_analyze,
        'versions': cmd_versions,
        'conflicts': cmd_conflicts,
        'search': cmd_search,
        'validate-config': cmd_validate_config,
        'scan-image': cmd_scan_image,
        'db': cmd_db,
        'compat': cmd_compat,
        'families': cmd_families,
        'resolve': cmd_resolve,
        'build-dist': cmd_build_dist,
        'simulate': cmd_simulate,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)
