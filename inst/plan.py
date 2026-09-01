"""The plan engine of the ported ``inst`` — resolve a selection into an
ordered, reviewable install plan before anything is written.

M1 builds the plan directly from the idb install records: products in
alphabetical order, files in idb order (directories before files, as the idb
is written).  Dependency-ordered sequencing, selection sets, and conflict
reporting arrive in M2 on top of ``pyirix.dist``'s analyzer/InstSimulator
semantics.

The plan is the review surface: it is JSON (``InstallPlan.to_json``) and is
what ``--plan`` prints — every file with its install path, mode, owner, size,
and source product.  A plan is by construction a dry run: M1/M2 never write
anything; the target layer (M2 ``TreeTarget``, M3 ``LinuxTarget``) executes a
plan, it does not re-derive one.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from pyirix.inst.media import MediaSource

__all__ = ["InstallFile", "InstallPlan", "build_plan"]


@dataclass
class InstallFile:
    """One planned installation: an idb record plus its source product."""

    path: str          # absolute install path, leading "/"
    type: str          # idb entry type: f, d, l, ...
    mode: int
    owner: str
    group: str
    size: int
    product: str
    subsystem: str = ""
    target: str = ""   # symlink/hardlink target (type l/h)


@dataclass
class InstallPlan:
    """An ordered install plan for a selection of products."""

    source: str            # dist directory the plan was built from
    target: str            # target descriptor ("tree", "disk:…"; M1 records only)
    dry_run: bool          # M1 plans are always dry runs
    files: list[InstallFile]
    products: list[str]    # in plan order

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files if f.type == "f")

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "dry_run": self.dry_run,
            "products": self.products,
            "totals": {"files": self.total_files, "bytes": self.total_bytes},
            "files": [asdict(f) for f in self.files],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json() + "\n")


def build_plan(
    media: MediaSource,
    target: str = "tree",
    products: list[str] | None = None,
) -> InstallPlan:
    """Build an install plan for *products* (default: every product in the
    source), in alphabetical product order with files in idb order."""
    selected = media.products
    if products is not None:
        wanted = set(products)
        selected = [p for p in selected if p.name in wanted]
        missing = wanted - {p.name for p in selected}
        if missing:
            raise _unknown_product_error(media, sorted(missing))

    files: list[InstallFile] = []
    ordered: list[str] = []
    for prod in selected:
        ordered.append(prod.name)
        for entry in prod.idb.entries:
            files.append(
                InstallFile(
                    path=entry.install_path,
                    type=entry.type,
                    mode=entry.mode,
                    owner=entry.owner,
                    group=entry.group,
                    size=entry.size,
                    product=prod.name,
                    subsystem=entry.subsystem,
                    target=entry.target,
                )
            )
    return InstallPlan(
        source=str(media.dist_dir),
        target=target,
        dry_run=True,
        files=files,
        products=ordered,
    )


def _unknown_product_error(media: MediaSource, missing: list[str]) -> Exception:
    known = ", ".join(p.name for p in media.products[:8])
    return ValueError(
        f"unknown product(s) {', '.join(missing)} in {media.dist_dir} (have: {known}…)"
    )
