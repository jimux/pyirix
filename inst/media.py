"""The media layer of the ported ``inst`` — IRIX software distributions.

An IRIX **distribution** (``dist``) is a directory of products.  Each product
is named by its install descriptor: ``<product>.idb`` holds one record per
file/directory/symlink (install path, mode, owner, subsystem, byte offset
into the archive); the same-stem file without an extension, when present, is
the binary spec file (``pd001`` magic — metadata: description, prerequisites,
hardware expressions); the ``<product>.sw*`` archives hold the bytes.

M1 is **idb-driven**: the idb is the authoritative install record, so product
discovery keys on ``.idb`` files and the spec is recorded (for M2's
dependency/conflict engine, which will consume it via ``pyirix.dist``'s
parser/analyzer) but not yet required.

Parsing is never duplicated: idb lines come from ``pyirix.dist.idb`` and
archive bytes from ``pyirix.dist.archive`` — the engine proven over the
5,134-disk inst_corpus.  This module only shapes them into the installer's
object model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pyirix.dist.idb import IDB, IDBEntry, parse_idb

SPEC_MAGIC = b"pd001"

__all__ = ["DistError", "MediaSource", "Product", "SPEC_MAGIC"]


class DistError(Exception):
    """A distribution directory could not be read as IRIX install media."""


@dataclass
class Product:
    """One product: an idb descriptor and everything it installs."""

    name: str
    idb_path: Path
    spec_path: Path | None
    idb: IDB
    # Subsystems named by the idb's own records (product.bundle.tag).
    subsystems: list[str] = field(default_factory=list)

    @property
    def has_spec(self) -> bool:
        return self.spec_path is not None

    def files(self) -> list[IDBEntry]:
        return self.idb.files()

    def total_size(self) -> int:
        return self.idb.total_size()

    @property
    def file_count(self) -> int:
        return len(self.idb.files())


def _is_dist_dir(path: Path) -> bool:
    """A dist directory holds at least one top-level ``.idb``."""
    try:
        for entry in path.iterdir():
            if entry.is_file() and entry.suffix == ".idb":
                return True
    except OSError:
        return False
    return False


def _collect_dist_dirs(entry: Path, found: list[Path]) -> None:
    """Collect dist dirs at *entry* or one level below it.

    *entry* is a candidate CD (or a directory holding several CDs).  A dist
    dir is recognized by its top-level idbs; when one is found the search
    stops there — a product directory is media, not a container.
    """
    if _is_dist_dir(entry):
        found.append(entry)
        return
    cand = entry / "dist"
    if cand.is_dir() and _is_dist_dir(cand):
        found.append(cand)
        return
    try:
        subs = sorted(entry.iterdir())
    except OSError:
        return
    for sub in subs:
        if not sub.is_dir():
            continue
        if _is_dist_dir(sub):
            found.append(sub)
            continue
        cand2 = sub / "dist"
        if cand2.is_dir() and _is_dist_dir(cand2):
            found.append(cand2)


@dataclass
class MediaSource:
    """A readable IRIX distribution directory (one CD's ``dist/`` or flat CD).

    ``MediaSource("…/IRIX_6.5.5_…/dist")`` — then ``.products`` (lazy) or
    ``MediaSource.find_dist_dirs("…/combo_extracted")`` to locate the dist
    directories of a whole (possibly multi-dist) medium.
    """

    dist_dir: Path

    def __post_init__(self) -> None:
        self.dist_dir = Path(self.dist_dir)
        if not self.dist_dir.is_dir():
            raise DistError(f"not a directory: {self.dist_dir}")
        # Eager: a MediaSource that names a non-dist fails at construction,
        # not at first use.  Discovery is one glob + the idb parses.
        self._products: list[Product] = self._discover()

    # ── discovery ──────────────────────────────────────────────────────

    @classmethod
    def find_dist_dirs(cls, root: str | Path) -> list[Path]:
        """Find dist directories under *root* (up to two levels deep).

        Real media is irregular: some CDs put products flat at the CD root,
        others under ``dist/``, combo discs carry several CDs (each with its
        own dist dir or flat products).  A directory counts as a dist dir
        when it holds a top-level ``.idb``.  Probes stop at the first idb, so
        this stays cheap even over a whole extracted combo.
        """
        root = Path(root)
        if not root.is_dir():
            raise DistError(f"not a directory: {root}")
        if _is_dist_dir(root):
            return [root]
        found: list[Path] = []
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            _collect_dist_dirs(entry, found)
        return found

    @property
    def products(self) -> list[Product]:
        return self._products

    def _discover(self) -> list[Product]:
        products: list[Product] = []
        for idb_path in sorted(self.dist_dir.glob("*.idb")):
            if not idb_path.is_file():
                continue
            try:
                idb = parse_idb(idb_path)
            except (OSError, ValueError) as exc:
                raise DistError(f"unreadable idb {idb_path}: {exc}") from exc
            if not idb.entries:
                continue  # a stray idb with no records is not a product
            # The spec is the same-stem file without extension, when present
            # and carrying the pd001 magic (a same-named non-spec file is no
            # spec at all — has_spec must stay False).
            spec_path: Path | None = None
            candidate = self.dist_dir / idb_path.stem
            if candidate.is_file() and not candidate.is_symlink():
                try:
                    if candidate.read_bytes()[:5] == SPEC_MAGIC:
                        spec_path = candidate
                except OSError:
                    pass
            products.append(
                Product(
                    name=idb_path.stem,
                    idb_path=idb_path,
                    spec_path=spec_path,
                    idb=idb,
                    subsystems=sorted(idb.by_subsystem()),
                )
            )
        if not products:
            raise DistError(f"no products (no readable *.idb) in {self.dist_dir}")
        return products

    # ── lookups ────────────────────────────────────────────────────────

    def product(self, name: str) -> Product:
        for prod in self.products:
            if prod.name == name:
                return prod
        raise DistError(
            f"product {name!r} not in {self.dist_dir} "
            f"(have {len(self.products)}: "
            + ", ".join(p.name for p in self.products[:8])
            + ("…" if len(self.products) > 8 else "")
            + ")"
        )
