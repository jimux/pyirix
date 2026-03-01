#!/usr/bin/env python3
"""Analyze IRIX distribution packages across multiple CDs.

Catalogs all packages (.idb files) from extracted dist/ directories,
extracts dependency information from spec files (binary files with
embedded plaintext dependency expressions), and detects version
conflicts and overlaps.

Usage:
    python3 tools/dist_analyzer.py catalog     # JSON: all subsystems -> CD sources
    python3 tools/dist_analyzer.py deps        # Dependency info from spec files
    python3 tools/dist_analyzer.py check       # Check for naming conflicts
    python3 tools/dist_analyzer.py trace PKG   # Trace dependency chain for a package
    python3 tools/dist_analyzer.py summary     # Overview of all CDs
"""

import argparse
import json
import os
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTRACT_BASE = PROJECT_ROOT / "software_library" / "extraced_irix_cds"

# CD display names for nice output
CD_NAMES = {
    "6.5-foundation-1": "Foundation 1",
    "6.5-foundation-2": "Foundation 2",
    "irix-6.5.22-overlay-1": "Overlays 1",
    "irix-6.5.22-overlay-2": "Overlays 2",
    "irix-6.5.22-overlay-3": "Overlays 3",
    "6.5-applications-2004": "Applications",
    "6.5-install-tools": "InstTools",
    # 6.5.5 era CDs
    "6.5.5_applications_812-0877-004": "Applications 6.5.5",
    "6.5.5_install-tools-overlays-1_812-0818-005": "InstTools+Overlays 6.5.5 1/2",
    "6.5.5_overlays-2_812-0819-005": "Overlays 6.5.5 2/2",
    "ONC3_NFS_812-0774-002": "ONC3/NFS 3",
    # MIPSpro compilers
    "mipspro_all_compiler_812-0925-001": "MIPSpro All-Compiler 7.3",
    "mipspro_74_c_compiler": "MIPSpro C 7.4",
    "mipspro_cpp_74_812-0400-010": "MIPSpro C++ 7.4",
    "mipspro_c_74_812-0707-010": "MIPSpro C 7.4 (standalone)",
    # Dev tools
    "prodev_suite_812-0768-003": "ProDev Suite",
    "prodev_workshop_293_812-0768-007": "ProDev WorkShop 2.9.3",
    "dev_foundation_13_812-0757-004": "Dev Foundation 1.3",
    "dev_libraries_812-0766-003": "Dev Libraries Feb 2002",
    # Demos
    "o2_demos_812-0780-002": "O2 Demos 1.3",
    "impact_demos_812-0527-001": "Impact Demos 6.2",
}

# Also try directory names with longer suffixes from previous extractions
CD_NAMES_ALT = {
    "6.5-foundation-1_812-0759-002": "Foundation 1",
    "6.5-foundation-2_812-0760-002": "Foundation 2",
}


def find_dist_dirs():
    """Find all extracted dist/ directories under EXTRACT_BASE.

    Returns list of (cd_name, dist_dir_path) tuples.
    """
    results = []
    if not EXTRACT_BASE.exists():
        return results

    for entry in sorted(EXTRACT_BASE.iterdir()):
        if not entry.is_dir():
            continue
        dist_dir = entry / "dist"
        if dist_dir.exists() and dist_dir.is_dir():
            cd_name = CD_NAMES.get(entry.name,
                                   CD_NAMES_ALT.get(entry.name, entry.name))
            results.append((cd_name, dist_dir))

    return results


_SUBSYS_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_+]*\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*$')


def parse_idb_subsystems(idb_path):
    """Parse an .idb file and extract subsystem names.

    IDB lines have fields: type perm user group dest src [subsystem] attrs...
    The subsystem name (e.g. "eoe.sw.base") is usually at position 6 but some
    older packages (e.g. websetup) place attribute tokens first and put the
    subsystem name last.  We try position 6 first; if it doesn't look like a
    subsystem name, we scan the remaining fields for one.

    Returns dict mapping subsystem names to their file counts and total size.
    """
    subsystems = defaultdict(lambda: {"files": 0, "total_size": 0})

    try:
        with open(idb_path, 'r', encoding='latin-1') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 7:
                    continue
                entry_type = parts[0]
                if entry_type not in ('d', 'f', 'l', 'c', 'b', 'p'):
                    continue

                # Try canonical position 6 first
                if _SUBSYS_RE.match(parts[6]):
                    package = parts[6]
                    rest_start = 7
                else:
                    # Older format: subsystem is appended after attribute tokens
                    package = None
                    for i in range(7, len(parts)):
                        if _SUBSYS_RE.match(parts[i]):
                            package = parts[i]
                            rest_start = i + 1
                            break
                    if package is None:
                        continue

                subsystems[package]["files"] += 1

                # Extract size from the attribute tokens after the subsystem
                rest = ' '.join(parts[rest_start:])
                m = re.search(r'(?<![a-z])size\((\d+)\)', rest)
                if m:
                    subsystems[package]["total_size"] += int(m.group(1))
    except Exception:
        pass

    return dict(subsystems)


def build_catalog(dist_dirs):
    """Build a catalog of all subsystems across all CDs.

    Returns dict:
    {
        "subsystem_name": {
            "sources": [
                {"cd": "Foundation 1", "idb": "eoe.idb", "files": 123, "size": 456789}
            ]
        }
    }
    """
    catalog = defaultdict(lambda: {"sources": []})

    for cd_name, dist_dir in dist_dirs:
        for idb_path in sorted(dist_dir.glob("*.idb")):
            subsystems = parse_idb_subsystems(idb_path)
            for subsys_name, info in subsystems.items():
                catalog[subsys_name]["sources"].append({
                    "cd": cd_name,
                    "idb": idb_path.name,
                    "files": info["files"],
                    "size": info["total_size"],
                })

    return dict(catalog)


def extract_deps_from_spec(spec_path):
    """Extract dependency expressions from a spec file.

    Spec files are binary files with embedded plaintext dependency
    expressions like:
        !noship && (eoe_eoe.sw.acct)
        eoe_eoe.sw.eoe || build_eoe.sw.eoe || irix_eoe.sw.eoe

    We extract these by scanning for three-part subsystem name patterns.
    """
    deps = []
    try:
        with open(spec_path, 'rb') as f:
            data = f.read()
    except Exception:
        return deps

    # Find all readable strings (sequences of printable ASCII)
    text_regions = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= 8:  # Minimum meaningful string
                text_regions.append((start, ''.join(current)))
            current = []
    if len(current) >= 8:
        text_regions.append((start, ''.join(current)))

    # Extract dependency expressions containing subsystem names
    # Pattern: product.type.subsystem (three dot-separated parts)
    subsys_pattern = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*\.[a-z]+\.[a-zA-Z_][a-zA-Z0-9_]*')

    for offset, text in text_regions:
        matches = subsys_pattern.findall(text)
        if matches:
            # Extract the full expression context
            deps.append({
                "offset": offset,
                "expression": text.strip(),
                "references": list(set(matches)),
            })

    return deps


def check_filename_conflicts(dist_dirs):
    """Check for filename conflicts between CDs.

    Returns list of (filename, [cd1, cd2, ...]) for files that appear
    on multiple CDs.
    """
    file_map = defaultdict(list)

    for cd_name, dist_dir in dist_dirs:
        for f in dist_dir.iterdir():
            if f.is_file():
                file_map[f.name].append(cd_name)

    conflicts = []
    for filename, sources in sorted(file_map.items()):
        if len(sources) > 1:
            conflicts.append((filename, sources))

    return conflicts


def trace_package(catalog, dep_map, package_name):
    """Trace the dependency chain for a specific package.

    Returns dict with package info and its dependencies.
    """
    result = {
        "package": package_name,
        "found": package_name in catalog,
        "sources": [],
        "dependencies": [],
        "dependents": [],
    }

    if package_name in catalog:
        result["sources"] = catalog[package_name]["sources"]

    # Find dependencies (packages this one depends on)
    if package_name in dep_map:
        result["dependencies"] = dep_map[package_name]

    # Find dependents (packages that depend on this one)
    for pkg, deps in dep_map.items():
        for dep in deps:
            if package_name in dep.get("references", []):
                result["dependents"].append(pkg)

    return result


# ── CLI commands ──────────────────────────────────────────────────

def cmd_catalog(args):
    """Output JSON catalog of all subsystems across all CDs."""
    dist_dirs = find_dist_dirs()
    if not dist_dirs:
        print(f"No extracted dist directories found under {EXTRACT_BASE}",
              file=sys.stderr)
        print("Run: python3 tools/extract_all_cds.py", file=sys.stderr)
        return 1

    catalog = build_catalog(dist_dirs)

    if args.json:
        print(json.dumps(catalog, indent=2))
    else:
        # Pretty-print
        print(f"Package catalog: {len(catalog)} subsystems from "
              f"{len(dist_dirs)} CDs\n")

        # Group by product (first part of subsystem name)
        products = defaultdict(list)
        for subsys in sorted(catalog.keys()):
            parts = subsys.split('.')
            product = parts[0] if parts else subsys
            products[product].append(subsys)

        for product in sorted(products.keys()):
            subsystems = products[product]
            print(f"\n{product} ({len(subsystems)} subsystems):")
            for subsys in subsystems:
                sources = catalog[subsys]["sources"]
                cds = ", ".join(s["cd"] for s in sources)
                total_files = sum(s["files"] for s in sources)
                total_size = sum(s["size"] for s in sources)
                size_str = f"{total_size // 1024}KB" if total_size > 0 else "?"
                print(f"  {subsys:50s} {total_files:5d} files  "
                      f"{size_str:>10s}  [{cds}]")

    return 0


def cmd_deps(args):
    """Extract and display dependency information from spec files."""
    dist_dirs = find_dist_dirs()
    if not dist_dirs:
        print(f"No extracted dist directories found under {EXTRACT_BASE}",
              file=sys.stderr)
        return 1

    all_deps = {}
    for cd_name, dist_dir in dist_dirs:
        # Spec files are extensionless files in dist/ that aren't .idb or .sw
        for f in sorted(dist_dir.iterdir()):
            if not f.is_file():
                continue
            if f.suffix in ('.idb', '.sw', '.man', '.books', '.relnotes'):
                continue
            # Skip very large files (likely data, not specs)
            if f.stat().st_size > 10 * 1024 * 1024:
                continue

            deps = extract_deps_from_spec(f)
            if deps:
                key = f"{cd_name}/{f.name}"
                all_deps[key] = deps

    if args.json:
        print(json.dumps(all_deps, indent=2))
    else:
        total_refs = 0
        for source, deps in sorted(all_deps.items()):
            refs = set()
            for dep in deps:
                refs.update(dep["references"])
            total_refs += len(refs)
            print(f"\n{source}: {len(refs)} referenced subsystems")
            for ref in sorted(refs):
                print(f"  {ref}")

        print(f"\nTotal: {len(all_deps)} spec files, "
              f"{total_refs} subsystem references")

    return 0


def cmd_check(args):
    """Check for filename conflicts and version overlaps."""
    dist_dirs = find_dist_dirs()
    if not dist_dirs:
        print(f"No extracted dist directories found under {EXTRACT_BASE}",
              file=sys.stderr)
        return 1

    print("Checking for filename conflicts across CDs...\n")

    conflicts = check_filename_conflicts(dist_dirs)
    if conflicts:
        print(f"Found {len(conflicts)} filename conflicts:")
        for filename, sources in conflicts:
            print(f"  {filename}: {', '.join(sources)}")
    else:
        print("No filename conflicts found (safe to combine)")

    # Check for subsystem version overlaps
    print("\nChecking for subsystem version overlaps...\n")
    catalog = build_catalog(dist_dirs)
    overlaps = []
    for subsys, info in sorted(catalog.items()):
        sources = info["sources"]
        if len(sources) > 1:
            overlaps.append((subsys, sources))

    if overlaps:
        print(f"Found {len(overlaps)} subsystems on multiple CDs:")
        for subsys, sources in overlaps:
            cds = ", ".join(f"{s['cd']}({s['files']})" for s in sources)
            print(f"  {subsys}: {cds}")
        print("\nNote: Overlapping subsystems are normal — overlays supersede "
              "foundation versions. inst handles version selection.")
    else:
        print("No subsystem overlaps found")

    return 0


def cmd_trace(args):
    """Trace the dependency chain for a specific package."""
    dist_dirs = find_dist_dirs()
    if not dist_dirs:
        print(f"No extracted dist directories found under {EXTRACT_BASE}",
              file=sys.stderr)
        return 1

    catalog = build_catalog(dist_dirs)

    # Build dependency map from spec files
    dep_map = {}
    for cd_name, dist_dir in dist_dirs:
        for f in sorted(dist_dir.iterdir()):
            if not f.is_file() or f.suffix in ('.idb', '.sw', '.man',
                                                  '.books', '.relnotes'):
                continue
            if f.stat().st_size > 10 * 1024 * 1024:
                continue
            deps = extract_deps_from_spec(f)
            if deps:
                dep_map[f"{cd_name}/{f.name}"] = deps

    result = trace_package(catalog, dep_map, args.package)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        pkg = result["package"]
        print(f"Package: {pkg}")
        print(f"Found in catalog: {result['found']}")

        if result["sources"]:
            print(f"\nSources ({len(result['sources'])}):")
            for s in result["sources"]:
                print(f"  {s['cd']}/{s['idb']} — "
                      f"{s['files']} files, {s['size'] // 1024}KB")

        if result["dependencies"]:
            print(f"\nDependency expressions ({len(result['dependencies'])}):")
            for dep in result["dependencies"]:
                print(f"  {dep['expression'][:100]}")
                for ref in dep.get("references", []):
                    in_catalog = "yes" if ref in catalog else "NO"
                    print(f"    -> {ref} (in catalog: {in_catalog})")

        if result["dependents"]:
            print(f"\nDepended on by ({len(result['dependents'])}):")
            for dep in sorted(set(result["dependents"])):
                print(f"  {dep}")

    return 0


def cmd_summary(args):
    """Show overview of all CDs and their contents."""
    dist_dirs = find_dist_dirs()
    if not dist_dirs:
        print(f"No extracted dist directories found under {EXTRACT_BASE}",
              file=sys.stderr)
        print("Run: python3 tools/extract_all_cds.py", file=sys.stderr)
        return 1

    print(f"IRIX 6.5 Distribution Summary")
    print(f"{'='*70}\n")

    total_files = 0
    total_size = 0
    total_subsystems = 0
    all_filenames = set()

    for cd_name, dist_dir in dist_dirs:
        # Count files
        files = list(dist_dir.iterdir())
        idb_files = [f for f in files if f.suffix == '.idb']
        sw_files = [f for f in files if f.suffix == '.sw']
        spec_files = [f for f in files
                      if f.is_file() and not f.suffix
                      and f.stat().st_size < 10 * 1024 * 1024]

        # Size
        cd_size = sum(f.stat().st_size for f in files if f.is_file())

        # Subsystems from .idb files
        subsystems = set()
        for idb_path in idb_files:
            subs = parse_idb_subsystems(idb_path)
            subsystems.update(subs.keys())

        print(f"{cd_name}")
        print(f"  Path: {dist_dir}")
        print(f"  Files: {len(files)} total "
              f"({len(idb_files)} .idb, {len(sw_files)} .sw, "
              f"{len(spec_files)} spec)")
        print(f"  Size: {cd_size // (1024*1024)}MB")
        print(f"  Subsystems: {len(subsystems)}")
        print()

        total_files += len(files)
        total_size += cd_size
        total_subsystems += len(subsystems)
        all_filenames.update(f.name for f in files if f.is_file())

    print(f"{'='*70}")
    print(f"Total: {len(dist_dirs)} CDs, {total_files} files, "
          f"{total_size // (1024*1024)}MB")
    print(f"Unique filenames: {len(all_filenames)}")
    print(f"Total subsystems (with overlaps): {total_subsystems}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IRIX distribution packages across multiple CDs"
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # catalog
    cat_p = subparsers.add_parser('catalog',
                                   help='JSON catalog of all subsystems')
    cat_p.add_argument('--json', action='store_true',
                       help='Output as JSON')

    # deps
    deps_p = subparsers.add_parser('deps',
                                    help='Extract dependency info from specs')
    deps_p.add_argument('--json', action='store_true',
                        help='Output as JSON')

    # check
    subparsers.add_parser('check',
                          help='Check for conflicts in combined set')

    # trace
    trace_p = subparsers.add_parser('trace',
                                     help='Trace dependency chain for a package')
    trace_p.add_argument('package', help='Package/subsystem name to trace')
    trace_p.add_argument('--json', action='store_true',
                         help='Output as JSON')

    # summary
    subparsers.add_parser('summary', help='Overview of all CDs')

    args = parser.parse_args()

    commands = {
        'catalog': cmd_catalog,
        'deps': cmd_deps,
        'check': cmd_check,
        'trace': cmd_trace,
        'summary': cmd_summary,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)
