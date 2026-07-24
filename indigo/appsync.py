#!/usr/bin/env python3
"""indigo-appsync: host Linux .desktop applications -> IRIX Icon Catalog entries.

Track 2 of the Indigo-Magic-on-Linux campaign (plan
``~/.claude/plans/is-4dwm-and-the-modular-pascal.md``; doc of record
``progress_notes/indigo_linux/00-README.md``).

Mechanism (verified against the corpus, see ``01-fftr-re.md`` /
``13-fti-harness-icons.md``): an IRIX Icon Catalog page is a *directory of
symlinks to executables*; the desktop types each target through the compiled
FTR database (``fftr`` -> ``.otr``), and the winning TYPE supplies the icon
(``.fti``) and the ``CMD OPEN`` action. So this module turns freedesktop
``.desktop`` entries into:

1. per-app launcher scripts ``<dataroot>/hostapps/bin/<id>`` carrying a
   *fixed-offset marker line* ``#hostapp=<id>`` at byte offset 10 (line 1 is
   always the exact 10-byte ``"#!/bin/sh\\n"``);
2. an ``indigo-launch`` dispatcher that restores the outer host DISPLAY,
   fills/strips the ``.desktop`` Exec field codes, and honors a per-app
   ``launch_display=inner`` override from ``~/.config/indigo/appsync.conf``;
3. ``<dataroot>/usr/lib/filetype/install/hostapps.ftr`` -- one TYPE per app,
   matched by the verified FTR idiom
   ``ascii && (string(10,K) == "#hostapp=<id>")`` (the same
   fixed-offset-string idiom ``netscape.ftr`` uses), with LEGEND from Name,
   SUPERTYPE Executable, CMD OPEN -> the launcher, ICON -> a genre ``.fti``;
4. catalog page symlink trees under
   ``<dataroot>/usr/lib/desktop/iconcatalog/pages/C/<Page>/<Name>``.

The full regenerate is **idempotent**: identical input .desktop state yields
byte-identical output, and a content hash lets callers skip the (expensive)
``fftr`` recompile when nothing changed.

fm is not ported yet, but this data pipeline is validated NOW because stock
IRIX ``fftr`` runs on the host under ``qemu-irixn32`` user-mode emulation --
see ``tests/test_indigo_appsync.py`` and the gate script in
``tmp/indigo-appsync/``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------
# .desktop scanning
# --------------------------------------------------------------------------

# freedesktop default application directories, most-specific last so user
# entries override system entries of the same id.
SYSTEM_APP_DIRS = ("/usr/share/applications", "/usr/local/share/applications")
USER_APP_DIR = "~/.local/share/applications"

# The desktop environment identity we present as, for OnlyShowIn/NotShowIn.
# The port runs its own 4Dwm session; we deliberately show desktop-agnostic
# apps and hide ones scoped to a foreign DE (GNOME/KDE control-panel shards).
CURRENT_DESKTOP = "INDIGO"


@dataclass
class DesktopApp:
    """A parsed, displayable freedesktop Application entry."""
    app_id: str                 # sanitized stable id (marker + FTR TYPE key)
    name: str
    exec_field: str             # raw Exec= value (with field codes)
    categories: tuple[str, ...] = ()
    comment: str = ""
    terminal: bool = False
    path: str = ""              # source .desktop path
    try_exec: str = ""

    @property
    def genre(self) -> str:
        return genre_for(self.categories)

    @property
    def page(self) -> str:
        return page_for(self.categories)


def _parse_desktop_group(text: str) -> dict[str, str]:
    """Return the key/value pairs of the [Desktop Entry] group only."""
    out: dict[str, str] = {}
    in_group = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_group = (line == "[Desktop Entry]")
            continue
        if not in_group:
            continue
        if "=" not in line:
            continue
        # Keys may carry a locale suffix Name[fr]=...; keep the unlocalized one.
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if "[" in key:            # localized variant -- ignore, keep C default
            continue
        out.setdefault(key, val)
    return out


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() == "true"


def sanitize_id(stem: str) -> str:
    """Map a .desktop id/stem to a safe, stable token for the marker + TYPE.

    Only ``[A-Za-z0-9_.-]`` survive; everything else collapses to ``_``. The
    marker offset stays fixed at 10 regardless of id length because line 1 is
    always exactly ``#!/bin/sh\\n``.
    """
    s = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
    return s or "app"


def parse_desktop_file(path: str) -> DesktopApp | None:
    """Parse one .desktop file; return None if it should not be shown.

    Honors Type==Application, NoDisplay, Hidden, OnlyShowIn/NotShowIn.
    """
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return None
    kv = _parse_desktop_group(text)
    if kv.get("Type", "Application") != "Application":
        return None
    if _truthy(kv.get("NoDisplay")) or _truthy(kv.get("Hidden")):
        return None
    exec_field = kv.get("Exec", "").strip()
    if not exec_field:
        return None                        # nothing to launch
    only = [d for d in kv.get("OnlyShowIn", "").split(";") if d]
    if only and CURRENT_DESKTOP not in only:
        return None
    notin = [d for d in kv.get("NotShowIn", "").split(";") if d]
    if CURRENT_DESKTOP in notin:
        return None
    stem = os.path.basename(path)
    if stem.endswith(".desktop"):
        stem = stem[: -len(".desktop")]
    cats = tuple(c for c in kv.get("Categories", "").split(";") if c)
    return DesktopApp(
        app_id=sanitize_id(stem),
        name=kv.get("Name", stem),
        exec_field=exec_field,
        categories=cats,
        comment=kv.get("Comment", ""),
        terminal=_truthy(kv.get("Terminal")),
        path=path,
        try_exec=kv.get("TryExec", "").strip(),
    )


def scan_desktop_entries(dirs: list[str] | None = None) -> list[DesktopApp]:
    """Scan system + user application dirs; dedupe by id (user wins).

    Returns apps sorted by id so the whole pipeline is deterministic.
    """
    if dirs is None:
        dirs = [os.path.expanduser(d) for d in SYSTEM_APP_DIRS]
        dirs.append(os.path.expanduser(USER_APP_DIR))
    by_id: dict[str, DesktopApp] = {}
    for d in dirs:                          # later dirs override earlier ones
        if not os.path.isdir(d):
            continue
        for entry in sorted(os.listdir(d)):
            if not entry.endswith(".desktop"):
                continue
            app = parse_desktop_file(os.path.join(d, entry))
            if app is not None:
                by_id[app.app_id] = app
    return [by_id[k] for k in sorted(by_id)]


# --------------------------------------------------------------------------
# genre + page mapping
# --------------------------------------------------------------------------

# freedesktop Category -> our 10 genre icons (M2.1). First match wins in the
# order the app lists its categories, checked most-specific-first per category.
_GENRE_RULES: tuple[tuple[str, str], ...] = (
    ("WebBrowser", "browser"),
    ("Email", "mail"),
    ("TerminalEmulator", "terminal"),
    ("Game", "game"),
    ("IDE", "development"),
    ("Development", "development"),
    ("AudioVideo", "media"),
    ("Audio", "media"),
    ("Video", "media"),
    ("Player", "media"),
    ("Music", "media"),
    ("Office", "office"),
    ("WordProcessor", "office"),
    ("Spreadsheet", "office"),
    ("Presentation", "office"),
    ("Settings", "settings"),
    ("HardwareSettings", "settings"),
    ("DesktopSettings", "settings"),
    ("System", "settings"),
    ("Graphics", "graphics"),
    ("2DGraphics", "graphics"),
    ("RasterGraphics", "graphics"),
    ("VectorGraphics", "graphics"),
    ("Photography", "graphics"),
    ("Network", "browser"),
)

GENRES = ("browser", "mail", "media", "terminal", "office",
          "settings", "development", "game", "graphics", "generic")


def genre_for(categories) -> str:
    cats = set(categories)
    for cat, genre in _GENRE_RULES:
        if cat in cats:
            return genre
    return "generic"


# Categories -> catalog page (plan Track 2 step 4).
_PAGE_RULES: tuple[tuple[str, str], ...] = (
    ("WebBrowser", "WebTools"),
    ("Network", "WebTools"),
    ("Settings", "ControlPanels"),
    ("HardwareSettings", "ControlPanels"),
    ("DesktopSettings", "ControlPanels"),
    ("AudioVideo", "MediaTools"),
    ("Audio", "MediaTools"),
    ("Video", "MediaTools"),
    ("Graphics", "MediaTools"),
    ("Development", "DesktopTools"),
    ("Utility", "DesktopTools"),
    ("System", "DesktopTools"),
)


def page_for(categories) -> str:
    cats = set(categories)
    for cat, page in _PAGE_RULES:
        if cat in cats:
            return page
    return "Applications"


# --------------------------------------------------------------------------
# marker arithmetic + launcher / ftr generation
# --------------------------------------------------------------------------

SHEBANG = "#!/bin/sh\n"           # EXACTLY 10 bytes -> marker starts at off 10
MARKER_OFFSET = 10
MARKER_PREFIX = "#hostapp="       # 9 bytes


def marker_line(app_id: str) -> str:
    """The full marker string ``#hostapp=<id>`` (no newline)."""
    return MARKER_PREFIX + app_id


def marker_match_len(app_id: str) -> int:
    """K in ``string(10,K)`` == len("#hostapp=<id>") == 9 + len(id)."""
    return len(MARKER_PREFIX) + len(app_id)


def launcher_script(app: DesktopApp) -> str:
    """The per-app launcher: shebang, fixed-offset marker, exec dispatcher."""
    # Line 1 must be the exact 10-byte shebang so the marker lands at offset 10.
    assert len(SHEBANG.encode()) == MARKER_OFFSET
    return (
        SHEBANG
        + marker_line(app.app_id) + "\n"
        + 'exec indigo-launch ' + app.app_id + ' "$@"\n'
    )


def verify_marker_offset(script: str, app_id: str) -> bool:
    """Assert the marker literally occupies bytes [10, 10+K) of the script."""
    data = script.encode()
    k = marker_match_len(app_id)
    return data[MARKER_OFFSET:MARKER_OFFSET + k] == marker_line(app_id).encode()


def _ftr_escape(s: str) -> str:
    """Escape a Python string for a double-quoted FTR string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def ftr_type(app: DesktopApp) -> str:
    """One FTR TYPE block for an app (matched by its fixed-offset marker)."""
    k = marker_match_len(app.app_id)
    legend = _ftr_escape(app.name)
    type_name = "HostApp_" + app.app_id.replace(".", "_").replace("-", "_")
    return (
        f"TYPE {type_name}\n"
        f'\tMATCH       ascii && (string({MARKER_OFFSET},{k}) == "{_ftr_escape(marker_line(app.app_id))}");\n'
        f"\tLEGEND      {legend}\n"
        f"\tSUPERTYPE   Executable\n"
        # CMD OPEN dispatches by app id, NOT $LEADER: fm runs the command via
        # `/bin/sh -c` with the file's (possibly Icon-Catalog, space-bearing,
        # $INDIGO_DATA_ROOT-overlay) path as $LEADER, and that path is not
        # host-executable (the pathmap interposer covers open/stat, not exec).
        # `indigo-launch <id>` is host-resolvable (on PATH) and reads the app's
        # real Exec line from hostapps/exec.tab, so double-click launch works
        # from the dirview AND the Icon Catalog. The launched child inherits
        # fm's env (fork+putenv), so INDIGO_DATA_ROOT / INDIGO_HOST_DISPLAY /
        # PATH all propagate.
        f"\tCMD OPEN    indigo-launch {app.app_id}\n"
        f"\tICON {{\n"
        f'\tinclude("iconlib/hostapp.{app.genre}.fti");\n'
        f"\t}}\n"
    )


def generate_ftr(apps: list[DesktopApp]) -> str:
    """The whole hostapps.ftr source (one TYPE per app)."""
    header = (
        "# hostapps.ftr -- GENERATED by indigo-appsync. Do not edit by hand.\n"
        "# One TYPE per host freedesktop application; matched by a fixed-offset\n"
        "# marker line in the launcher script it types.\n\n"
    )
    return header + "\n".join(ftr_type(a) for a in apps) + "\n"


# --------------------------------------------------------------------------
# indigo-launch dispatcher
# --------------------------------------------------------------------------

INDIGO_LAUNCH = r'''#!/bin/sh
# indigo-launch -- GENERATED by indigo-appsync.
# Dispatch a host freedesktop application by its <id>, restoring the OUTER
# host display so the app opens on the real desktop (not inside the retro
# Xephyr session), unless the per-app/global config says launch_display=inner.
#
#   usage: indigo-launch <id> [args...]
#
# Config: ~/.config/indigo/appsync.conf  (key = value lines)
#   launch_display = outer            # global default
#   launch_display.<id> = inner       # per-app override
#
id="$1"; shift
[ -n "$id" ] || { echo "indigo-launch: missing <id>" >&2; exit 2; }

conf="${XDG_CONFIG_HOME:-$HOME/.config}/indigo/appsync.conf"
mode=outer
if [ -f "$conf" ]; then
    g=`sed -n 's/^[[:space:]]*launch_display[[:space:]]*=[[:space:]]*\([a-z]*\).*/\1/p' "$conf" | head -1`
    [ -n "$g" ] && mode="$g"
    p=`sed -n "s/^[[:space:]]*launch_display\.$id[[:space:]]*=[[:space:]]*\([a-z]*\).*/\1/p" "$conf" | head -1`
    [ -n "$p" ] && mode="$p"
fi

if [ "$mode" = outer ]; then
    # Restore the outer host display saved when the retro session started.
    if [ -n "$INDIGO_HOST_DISPLAY" ]; then
        DISPLAY="$INDIGO_HOST_DISPLAY"; export DISPLAY
    fi
fi

# Drop the exec-path-translation shim (libindigoexec.so) before running the
# real host application: it exists only to let fm's shell resolve the
# IRIX-canonical launcher path in the Icon Catalog, and must never be inherited
# by the host app itself.
unset LD_PRELOAD

# Locate the launcher script for <id> and read its Exec line back out of the
# generated exec-table, stripping freedesktop field codes (%f %F %u %U %i %c
# %k %d %D %n %N %v %m); %% -> literal %.
root="${INDIGO_DATA_ROOT:-$HOME/.local/share/indigo}"
table="$root/hostapps/exec.tab"
line=`grep "^$id	" "$table" 2>/dev/null | head -1`
cmd=`printf '%s' "$line" | cut -f2-`
[ -n "$cmd" ] || { echo "indigo-launch: no exec for '$id'" >&2; exit 3; }

# Strip field codes. Deprecated/single-letter codes that take no runtime value
# here are simply removed; %% becomes %.
cmd=`printf '%s' "$cmd" | sed -e 's/%[fFuUickdDnNvm]//g' -e 's/%%/%/g'`

# CRITICAL: drop the launcher dir ($root/hostapps/bin) from PATH before running
# the real app.  The launcher scripts are named by app id, and an id can equal
# the target binary name (e.g. id "xclock" whose Exec is "xclock"); with the
# launcher dir still on PATH the "real" command would re-resolve to THIS
# launcher and recurse -> a fork bomb.  Filtering the launcher dir makes the
# app name resolve to the genuine host binary.
lbin="$root/hostapps/bin"
newpath=""
oldifs="$IFS"; IFS=:
for d in $PATH; do
    [ "$d" = "$lbin" ] && continue
    if [ -z "$newpath" ]; then newpath="$d"; else newpath="$newpath:$d"; fi
done
IFS="$oldifs"
PATH="$newpath"; export PATH

exec /bin/sh -c "$cmd \"\$@\"" indigo-launch "$@"
'''


# --------------------------------------------------------------------------
# full pipeline
# --------------------------------------------------------------------------

FTR_INSTALL_REL = "usr/lib/filetype/install"
ICONLIB_REL = FTR_INSTALL_REL + "/iconlib"
PAGES_REL = "usr/lib/desktop/iconcatalog/pages/C"
HOSTAPPS_BIN_REL = "hostapps/bin"


def _genre_icons_dir() -> Path:
    return Path(__file__).resolve().parent / "genre_icons"


def _content_hash(apps: list[DesktopApp]) -> str:
    """Stable hash of everything that affects generated output."""
    h = hashlib.sha256()
    for a in apps:
        rec = "\x00".join((
            a.app_id, a.name, a.exec_field, a.genre, a.page,
            ";".join(a.categories),
        ))
        h.update(rec.encode())
        h.update(b"\x1e")
    # Fold in the genre-icon set so an icon edit re-triggers the recompile.
    for p in sorted(_genre_icons_dir().glob("*.fti")):
        h.update(p.read_bytes())
    return h.hexdigest()


@dataclass
class AppsyncResult:
    data_root: str
    apps: list[DesktopApp]
    ftr_path: str
    launch_dir: str
    changed: bool
    content_hash: str
    pages: dict[str, list[str]] = field(default_factory=dict)
    genre_counts: dict[str, int] = field(default_factory=dict)
    page_counts: dict[str, int] = field(default_factory=dict)


def _write_exec(path: str, text: str) -> None:
    Path(path).write_text(text)
    os.chmod(path, 0o755)


def run_appsync(dest: str | None = None,
                dirs: list[str] | None = None,
                force: bool = False,
                single_page: str | None = None) -> AppsyncResult:
    """Full, idempotent regenerate of the appsync data pipeline.

    Returns the result and whether anything changed (``changed`` False lets a
    caller skip the fftr recompile). Does NOT compile ``.otr`` (that is the
    ported-fftr / stock-fftr step, driven separately).

    ``single_page`` (e.g. ``"HostApps"``) routes every host app onto ONE
    dedicated Icon Catalog page instead of the per-Categories page map. The
    live overlay uses this so appsync never touches the imported catalog's
    pristine pages (it only creates/cleans its own dedicated page dir).
    """
    from pyirix.indigo.config import resolve_data_root
    root = resolve_data_root(dest)
    apps = scan_desktop_entries(dirs)

    def _page(app: DesktopApp) -> str:
        return single_page or app.page

    chash = _content_hash(apps)
    hash_path = os.path.join(root, "hostapps", ".appsync-hash")
    prev = None
    if os.path.isfile(hash_path):
        prev = Path(hash_path).read_text().strip()
    changed = force or (prev != chash)

    # Directories.
    bin_dir = os.path.join(root, HOSTAPPS_BIN_REL)
    iconlib_dir = os.path.join(root, ICONLIB_REL)
    install_dir = os.path.join(root, FTR_INSTALL_REL)
    pages_root = os.path.join(root, PAGES_REL)
    for d in (bin_dir, iconlib_dir, install_dir, pages_root):
        os.makedirs(d, exist_ok=True)

    # 1. launcher scripts + an id->Exec table for indigo-launch.
    #    Wipe stale launchers so removals sync.
    for old in os.listdir(bin_dir):
        os.remove(os.path.join(bin_dir, old))
    exec_rows = []
    for a in apps:
        script = launcher_script(a)
        assert verify_marker_offset(script, a.app_id), a.app_id
        _write_exec(os.path.join(bin_dir, a.app_id), script)
        exec_rows.append(f"{a.app_id}\t{a.exec_field}")
    Path(os.path.join(root, "hostapps", "exec.tab")).write_text(
        "\n".join(exec_rows) + ("\n" if exec_rows else ""))

    # 2. indigo-launch dispatcher.
    _write_exec(os.path.join(bin_dir, "indigo-launch"), INDIGO_LAUNCH)

    # 3. genre iconlib (install the 10 icons under the fftr-visible name).
    for genre in GENRES:
        src = _genre_icons_dir() / f"genre.{genre}.fti"
        if src.is_file():
            shutil.copyfile(src, os.path.join(iconlib_dir,
                                              f"hostapp.{genre}.fti"))

    # 4. hostapps.ftr.
    ftr_path = os.path.join(install_dir, "hostapps.ftr")
    Path(ftr_path).write_text(generate_ftr(apps))

    # 5. catalog page symlink trees (relative links to the launchers).
    pages: dict[str, list[str]] = {}
    # Clean our own page dirs first (idempotent; leaves foreign pages alone).
    for a in apps:
        pages.setdefault(_page(a), [])
    for page in list(pages):
        pdir = os.path.join(pages_root, page)
        if os.path.isdir(pdir):
            for old in os.listdir(pdir):
                op = os.path.join(pdir, old)
                if os.path.islink(op):
                    os.unlink(op)
    seen: dict[str, set[str]] = {}
    for a in apps:
        apage = _page(a)
        pdir = os.path.join(pages_root, apage)
        os.makedirs(pdir, exist_ok=True)
        # Page entry name = the app's display Name, uniquified within a page.
        base = re.sub(r"[/\x00]", "_", a.name).strip() or a.app_id
        used = seen.setdefault(apage, set())
        name = base
        n = 2
        while name in used:
            name = f"{base} ({n})"
            n += 1
        used.add(name)
        link = os.path.join(pdir, name)
        target = os.path.relpath(os.path.join(bin_dir, a.app_id), pdir)
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        os.symlink(target, link)
        pages[apage].append(name)

    # Record the content hash last (so a crash mid-run re-runs next time).
    Path(hash_path).write_text(chash + "\n")

    genre_counts: dict[str, int] = {}
    page_counts: dict[str, int] = {}
    for a in apps:
        genre_counts[a.genre] = genre_counts.get(a.genre, 0) + 1
        page_counts[_page(a)] = page_counts.get(_page(a), 0) + 1

    return AppsyncResult(
        data_root=root, apps=apps, ftr_path=ftr_path, launch_dir=bin_dir,
        changed=changed, content_hash=chash, pages=pages,
        genre_counts=genre_counts, page_counts=page_counts,
    )
