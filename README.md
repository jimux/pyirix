# pyirix

Python library for working with SGI/IRIX software. Reads SGI EFS filesystems
and parses IRIX distribution packages and spec files. **No QEMU required.**

For QEMU orchestration tools (session management, disk creation, automated
installation, disc image catalog), see the companion `pyirix_qemu` package.

---

## Dependencies

- Python 3.8+
- Standard library only (no third-party dependencies)
- Optional: `capstone` for disassembly in the analysis tools (`sgi_mcp`), but
  not required by `pyirix` itself

---

## Installation

```bash
# Editable install from source
pip install -e /path/to/workspace/pyirix

# Or just add to PYTHONPATH
export PYTHONPATH=/path/to/workspace:$PYTHONPATH
```

---

## `pyirix.efs` — EFS Filesystem Tools

Reads and extracts SGI EFS (Extent File System) partitions from raw disc images.
Handles the SGI disk volume header, partition tables, superblocks, inodes,
extents, and symlinks.

### Key functions

```python
from pyirix.efs.reader import (
    find_efs_partition,   # Locate EFS partition in a disc image
    read_superblock,      # Parse EFS superblock
    read_inode,           # Read a single inode
    extract_recursive,    # Extract a directory tree
    EFS_ROOT_INODE,       # Inode number of the root directory (2)
)
```

### Usage

```python
from pyirix.efs.reader import find_efs_partition, read_superblock, extract_recursive, EFS_ROOT_INODE

with open("Foundation1.img", "rb") as f:
    # Find the EFS partition inside the SGI disk image
    result = find_efs_partition(f)
    if not result:
        print("No EFS partition found")
    else:
        part_offset, part_size = result
        sb = read_superblock(f, part_offset)

        # Extract only the dist/ directory
        stats = extract_recursive(
            f, part_offset, sb, EFS_ROOT_INODE,
            current_path="/", dest_dir="/tmp/extracted",
            path_filter="dist"
        )
        print(f"Extracted {stats['files']} files, {stats['symlinks']} symlinks")
```

### CLI

```bash
# Show partition info
python -m pyirix.efs.reader info Foundation1.img

# List filesystem contents
python -m pyirix.efs.reader list Foundation1.img

# Extract to a directory
python -m pyirix.efs.reader extract Foundation1.img /tmp/output
```

### Bulk extraction

```python
from pyirix.efs.extract import extract_cd_set

# Extract dist/ from all CDs in a directory
extract_cd_set("/path/to/images", "/tmp/staging")
```

---

## `pyirix.dist` — IRIX Distribution Package Analysis

Parses IRIX distribution `.idb` spec files, resolves package dependencies, detects conflicts, and simulates installation state. Also provides tools to combine multiple distribution directories into a single composite image. Note that the exact behavior of `Inst>` isn't clearly defined in some cases, and this is a best-effort. Some quirks of resolution I haven't been able to replicate, namely around malformed `.idb` files.

### Key classes and functions

```python
from pyirix.dist.analyzer import Corpus, parse_idb_subsystems

# Load all .idb files from a dist directory
corpus = Corpus.load_dir("/path/to/dist")

# Check for file conflicts on an Indy (IP24) hardware config
conflicts = corpus.conflicts(hw="IP24")

# Parse subsystems from a single .idb file
subsystems = parse_idb_subsystems("/path/to/dist/eoe.sw.idb")
for name, info in subsystems.items():
    print(f"{name}: {info['files']} files, {info['total_size']} bytes")
```

```python
from pyirix.dist.parser import parse_idb_file, DepExprParser

# Parse a raw .idb file into a list of records
records = parse_idb_file("/path/to/dist/c_dev.sw.idb")

# Evaluate a dependency expression
parser = DepExprParser("eoe.sw.base && !patch_tools")
result = parser.evaluate(installed={"eoe.sw.base"})
```

```python
from pyirix.dist.pkg_selector import select_packages

# Select packages for installation, resolving deps
selected = select_packages(corpus, requested=["c_dev", "c++_dev"])
```

```python
from pyirix.dist.combine import build_combo_image

# Build a combined EFS image from multiple dist directories
build_combo_image(
    dist_dirs=["/tmp/mipspro/dist", "/tmp/devtools/dist"],
    output="/tmp/combo.img",
    size_mb=2048,
)
```

### CLI

```bash
# Catalog all subsystems in a dist directory
python -m pyirix.dist.analyzer catalog /path/to/dist

# Parse and dump an .idb file
python -m pyirix.dist.parser /path/to/dist/eoe.sw.idb

# Check for conflicts
python -m pyirix.dist.analyzer conflicts /path/to/dist --hw IP24
```

---

## Module Summary

| Module | Purpose |
|--------|---------|
| `pyirix.efs.reader` | EFS partition finder, superblock/inode parser, recursive extractor |
| `pyirix.efs.extract` | High-level CD set extractor; wraps reader with fallback to efsextract |
| `pyirix.dist.analyzer` | Corpus loader, subsystem parser, conflict detector |
| `pyirix.dist.parser` | Low-level `.idb` file parser; dependency expression evaluator |
| `pyirix.dist.pkg_analyzer` | Package metadata analysis and version comparison |
| `pyirix.dist.pkg_selector` | Dependency-aware package selection |
| `pyirix.dist.combine` | Multi-source dist combiner; builds composite EFS images |
| `pyirix.dist.patch` | Applies patches to dist directories |
