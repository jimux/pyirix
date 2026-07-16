#!/usr/bin/env python3
"""The asset manifest — the path-glob table that says *which* files the
Indigo-on-Linux port needs out of a user's IRIX media, and where under the
data root they land.

Every entry maps a subtree of the IRIX install (`prefix`, an install-path
relative to `/`) to the SAME relative path under the port's data root. So
`usr/lib/X11/schemes/Base/Base` on the IRIX side becomes
`<data_root>/usr/lib/X11/schemes/Base/Base` — the port then needs only one
path-translation shim (data-root prefix) rather than per-asset knowledge.

Each entry also carries verification thresholds and a "count kind" so the
`verify` command can assert a populated, sane import without hard-coding
counts elsewhere. Thresholds are deliberately conservative — enough to
prove a real import happened, not to demand a specific media revision.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ManifestEntry:
    name: str                       # logical asset category
    prefix: str                     # install path (POSIX, no leading '/')
    products: tuple[str, ...]       # inst product hints (informational)
    min_count: int                  # verify: minimum matched items
    count_kind: str                 # 'dirs' | 'files' | 'ext:<suffix>'
    required: bool = True           # verify fails if a required category is empty
    post_step: str = ""             # e.g. 'mkfontdir'
    note: str = ""

    def counts(self, relpaths: list[str]) -> int:
        """Count matched items of this entry's `count_kind` from a list of
        imported relpaths (all already under this entry's prefix)."""
        if self.count_kind == "dirs":
            # count immediate child directories of the prefix
            depth = self.prefix.count("/") + 1
            tops = set()
            for r in relpaths:
                parts = r.split("/")
                if len(parts) > depth:
                    tops.add(parts[depth])
            return len(tops)
        if self.count_kind.startswith("ext:"):
            suf = self.count_kind[4:]
            return sum(1 for r in relpaths if r.endswith(suf))
        # default: plain file count
        return len(relpaths)


# The manifest. Order is import order (informational).
MANIFEST: tuple[ManifestEntry, ...] = (
    ManifestEntry(
        name="schemes",
        prefix="usr/lib/X11/schemes",
        products=("x_eoe", "motif_eoe", "desktop_eoe"),
        min_count=1, count_kind="dirs",
        note="colour/font/spec palettes; each subdir is one scheme",
    ),
    ManifestEntry(
        name="fonts",
        prefix="usr/lib/X11/fonts",
        products=("x_eoe.sw.Xfonts",),
        min_count=1, count_kind="dirs", required=False,
        post_step="mkfontdir",
        note="run mkfontdir/mkfontscale on imported font dirs post-import",
    ),
    ManifestEntry(
        name="filetype",
        prefix="usr/lib/filetype",
        products=("desktop_base.sw.FileTypingRules",),
        min_count=100, count_kind="ext:.fti",
        note=".ftr/.otr/.ctr sources + iconlib .fti vector icons",
    ),
    ManifestEntry(
        name="iconcatalog",
        prefix="usr/lib/desktop/iconcatalog",
        products=("desktop_eoe",),
        min_count=1, count_kind="files", required=False,
        note="catalog page dirs are trees of symlinks to executables",
    ),
    ManifestEntry(
        name="app-defaults",
        prefix="usr/lib/X11/app-defaults",
        products=("x_eoe", "desktop_eoe", "dmedia_eoe"),
        min_count=1, count_kind="files", required=False,
    ),
    ManifestEntry(
        name="rgb-colors",
        prefix="usr/lib/X11/rgb.txt",
        products=("x_eoe.sw.Server",),
        min_count=1, count_kind="files", required=False,
        note="SGI-named X colors (SGIGray*, SGIDarkGray, sgilightblue, ...) "
             "referenced by schemes/app-defaults but absent from stock Linux "
             "rgb.txt; single file only — rgb.dir/rgb.pag are a regenerable "
             "dbm cache of it (rebuild with `rgb -o <dir> rgb.txt` if needed, "
             "not imported here).",
    ),
    ManifestEntry(
        name="sounds",
        prefix="usr/share/data/sounds",
        products=("dmedia_eoe", "soundscheme"),
        min_count=1, count_kind="files", required=False,
    ),
    ManifestEntry(
        name="savers",
        prefix="usr/lib/X11/savers",
        products=("desktop_eoe",),
        min_count=10, count_kind="files", required=False,
        note="per-saver X-resource defaults + modules dir listing",
    ),
    ManifestEntry(
        name="backgrounds",
        prefix="usr/lib/X11/system.backgrounds",
        products=("desktop_eoe.sw.control_panels",),
        min_count=1, count_kind="files", required=False,
        note="the background registry (names + `-solid`/`-bitmap` "
             "descriptions for every entry in the Background customize "
             "panel); first entry is the genuine default `Solid "
             "sgiLightBlue`, NOT the dithered-granite look users remember "
             "(see progress_notes/indigo_linux/19-desktop-fidelity.md "
             "bug 2). Single file — its `-bitmap` entries resolve into "
             "the background-bitmaps category below.",
    ),
    ManifestEntry(
        name="background-bitmaps",
        prefix="usr/include/X11/bitmaps/sgidesktop",
        products=("desktop_eoe.sw.control_panels", "desktop_eoe.sw.envm",
                  "sysadmdesktop.sw.base", "sysadmdesktop.sw.sysadm"),
        min_count=10, count_kind="files", required=False,
        note="whole directory imported as a tree, like other categories "
             "here: the background xpm/bmp/xbm textures referenced by "
             "system.backgrounds (granite2small, midgranitesmall, marble/"
             "linen/pattern*/scribble/...) share this dir with unrelated "
             "fm(bitmaps) and sysadmdesktop icon bitmaps — not filtered "
             "out, same tree-import policy as e.g. iconcatalog.",
    ),
    ManifestEntry(
        name="granite-bitmap",
        prefix="usr/include/X11/bitmaps/granite",
        products=("x_eoe.sw.eoe",),
        min_count=1, count_kind="files", required=False,
        note="4Dwm's own no-desktop fallback background bitmap "
             "(app-defaults `*defaultBackgroundDescription: -bitmap "
             "/usr/include/X11/bitmaps/granite ...`); lives under x_eoe, "
             "a sibling of usr/include/X11/bitmaps/ that also holds many "
             "unrelated cursor/pattern bitmaps (gray, box6, left_ptr, "
             "...) — deliberately NOT imported by prefixing the whole "
             "bitmaps/ dir, so this is its own single-file entry.",
    ),
)


def by_name(name: str) -> ManifestEntry | None:
    for e in MANIFEST:
        if e.name == name:
            return e
    return None


def match_entry(install_path: str) -> ManifestEntry | None:
    """Return the manifest entry whose prefix owns `install_path`
    (POSIX, leading slash tolerated), or None."""
    p = install_path.lstrip("/")
    for e in MANIFEST:
        if p == e.prefix or p.startswith(e.prefix + "/"):
            return e
    return None


def prefixes() -> list[str]:
    return [e.prefix for e in MANIFEST]
