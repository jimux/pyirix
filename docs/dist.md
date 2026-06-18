# `pyirix.dist` — IRIX Distribution Package Analysis

> Part of the [pyirix documentation](../README.md).

Tools for understanding and assembling IRIX install media: parse `.idb` manifests and binary spec files, resolve dependency expressions, detect version/conflict/hardware problems the way `inst` would, extract files from `.sw` archives, and build composite EFS install images.

> The exact behavior of IRIX's `inst` (`Inst>`) is not fully specified; this is a faithful best-effort. Some resolution quirks — especially around malformed `.idb` files — are not perfectly reproduced.

## The packaging model

An IRIX product is described by a binary **spec file** (magic `pd001`) plus one or more **`.idb`** manifests and **`.sw`** archives. The spec file lists images (`sw`, `man`, …), subsystems (`base`, …), version comparators, prerequisites with version ranges, and hardware expressions. The `.idb` is a text manifest: one line per installed file with type, mode, owner, install path, archive path, subsystem, and key-value flags (`size(N)`, `off(N)`, `cmpsize(N)`, `symval(...)`). The `.sw` is a flat concatenation of per-file records, each LZW-compressed (`.Z`/`compress`, magic `\x1f\x9d`) or stored.

Two parsers exist deliberately: `parser.parse_spec` follows the length-prefixed binary layout exactly (recovers prereqs **with version ranges**), while `analyzer.extract_deps_from_spec` / `pkg_analyzer.extract_subsystem_deps` are faster proximity heuristics that find dep expressions near subsystem names but don't decode version ranges. `Corpus.conflicts()` uses the precise parser; `InstSimulator` uses the heuristic.

## Module map

| Module | Role |
|--------|------|
| `analyzer` | Filesystem scan of extracted CDs: catalog subsystems, text-scan deps, conflicts |
| `parser` | High-fidelity binary spec parser; the `Corpus` index and conflict report |
| `pkg_analyzer` | Big toolbox: `DepExprParser`, `InstSimulator`, `PackageDatabase` (SQLite), family/platform resolution, EFS image scanning |
| `pkg_selector` | Curses TUI for picking product families and resolving a minimal CD set |
| `combine` | Build a combined EFS install image from multiple dist directories |
| `idb` | Structured `.idb` parser → `IDB`/`IDBEntry` objects |
| `audit` | Cross-check installed files on a disk against `.idb` manifests |
| `archive` | Extract files out of `.sw` archives using `.idb` offsets |
| `patch` | Fix the malformed `motif_eoe.sw64.uil` spec record |

## Cataloging and parsing

```python
from pyirix.dist.analyzer import find_dist_dirs, build_catalog, parse_idb_subsystems

dirs = find_dist_dirs()                       # [(cd_label, dist_path), ...] under the extracted-CDs tree
catalog = build_catalog(dirs)                 # {subsystem: {"sources": [{cd, idb, files, size}, ...]}}

subs = parse_idb_subsystems("/path/dist/eoe.sw.idb")   # {name: {"files": int, "total_size": int}}
```

```python
from pyirix.dist.idb import parse_idb

idb = parse_idb("/path/dist/4Dwm.idb")        # IDB(product, path, entries=[IDBEntry, ...])
for e in idb.files():                          # type == "f" entries
    print(e.install_path, e.size, e.subsystem, e.offset)
print("total:", idb.total_size())
```

## Dependency expressions and conflict detection

`DepExprParser` is a recursive-descent evaluator for spec dependency strings (`&&`, `||`, `!`, parentheses, subsystem references, and `VAR=VAL` hardware tests like `CPUBOARD=IP22`, `MODE=64bit`, `GFXBOARD=NEWPORT`). A subsystem reference is true if it's installed; an unknown literal evaluates conservatively to true.

```python
from pyirix.dist.pkg_analyzer import DepExprParser, TARGET_CONFIGS

p = DepExprParser(available_subsystems={"eoe.sw.base"}, target=TARGET_CONFIGS["indy"])
p.evaluate("eoe.sw.base && CPUBOARD=IP22")    # -> True on an Indy
```

`Corpus` indexes a whole distribution (newest version of each subsystem wins) and reports the conflicts `inst` would hit on a given hardware config:

```python
from pyirix.dist.parser import Corpus, HardwareConfig

corpus = Corpus()
corpus.load_dir("/path/to/dist")              # also: load_dirs, load_tardist, load_tardist_dir
report = corpus.conflicts(HardwareConfig.indy())
print(report.summary())                       # counts by kind
for c in report.by_kind("missing_prereq"):
    print(c.subsystem, "->", c.detail)
# report.keep_set is the set of subsystems to `keep` in inst before `go`
```

Conflicts come in four kinds: `hw_excluded` (every file filtered out by `mach()` on this hardware), `hw_restricted` (spec `hw_expr` evaluates false), `missing_prereq` (a prerequisite isn't in the corpus), and `version_range` (a prerequisite is present but its version falls outside the required `[min,max]`).

## Simulating an install and resolving families

`InstSimulator` mirrors `inst`'s `keep * + install standard` selection (`.sw` always; `.sw32`/`.sw64` by mode) and reports the resulting conflicts. `FamilyResolver` works at a higher level: given product "families" (`base_os`, `desktop`, `c`, `c++`, `mipspro`, …) it expands implicit dependencies, queries the SQLite `PackageDatabase` for V-code-compatible images, and runs a greedy set-cover to pick the minimal set of CD images that supply them.

```python
from pyirix.dist.pkg_analyzer import PackageDatabase, FamilyResolver

db = PackageDatabase()                        # SQLite cache of scanned images
db.scan_or_lookup("/images/MIPSpro_7.4.4.img")   # hash -> lookup, scan-on-miss, store
res = FamilyResolver(db, target_version="6.5", platform="indy").resolve(["c", "c++"])
for md5, filename, products in res.selected_images:
    print(filename, "covers", products)
```

## Building a combined image

`combine.py` collects files from several extracted dist directories and writes a single bootable EFS image (with SGI volume header), running pre-flight conflict analysis and an inst simulation first. It supports per-CD layout (each CD in its own subdirectory) or a flat single-`dist/` layout where later CDs supersede earlier ones.

```python
from pyirix.dist.combine import find_dist_dirs, CONFIGS
# Named configs: "6.5", "6.5.5", "mipspro", "devtools-655", "apps-655"
```

## Extracting from `.sw` archives and auditing

```python
from pyirix.dist.idb import parse_idb
from pyirix.dist.archive import extract_to_dir

idb = parse_idb("/path/dist/4Dwm.idb")
n = extract_to_dir("/path/dist/4Dwm.sw", idb, "/tmp/4Dwm", filter_subsystem="4Dwm.sw.4Dwm")
print(n, "files written")                     # LZW-decompressed via gunzip where needed
```

```python
from pyirix.dist.audit import audit_disk
report = audit_disk("disk.qcow2", "/images/Foundation1.img")   # compares installed files vs .idb
print(report.summary())                       # complete / partial / empty per product
```

## CLIs

```bash
# analyzer — operates on the auto-discovered extracted-CD tree
python -m pyirix.dist.analyzer catalog [--json]
python -m pyirix.dist.analyzer check                      # filename + version conflicts
python -m pyirix.dist.analyzer trace <package> [--json]
python -m pyirix.dist.analyzer summary

# parser — load a corpus and print the inst keep-set for a target
python -m pyirix.dist.parser --target indy --dist /path/to/dist [--tardist FILE] [-v]

# pkg_analyzer — the big toolbox
python -m pyirix.dist.pkg_analyzer analyze   --cds DIR...
python -m pyirix.dist.pkg_analyzer resolve   c c++ --platform indy
python -m pyirix.dist.pkg_analyzer scan-image FILE...
python -m pyirix.dist.pkg_analyzer simulate  --target indy --dist DIR...

# pkg_selector — interactive family picker
python -m pyirix.dist.pkg_selector --platform indy --target 6.5

# combine — build/check/verify a composite EFS image
python -m pyirix.dist.combine build  -o combo.img --source DIR
python -m pyirix.dist.combine check  --source DIR
python -m pyirix.dist.combine verify -o combo.img

# idb / archive / audit / patch
python -m pyirix.dist.idb     <file.idb> [--json] [--subsystem NAME] [--files-only]
python -m pyirix.dist.archive --idb F.idb --sw F.sw --out DIR [--subsystem NAME]
python -m pyirix.dist.audit   --disk disk.qcow2 --dist-image EFS.img [--missing-only]
python -m pyirix.dist.patch   <motif_eoe_spec> [--verify] [--dry-run]
```
