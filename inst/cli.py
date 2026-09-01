"""The command line of the ported ``inst``.

Two faces, deliberately separated:

**Stock surface** — the single-character option set of IRIX ``inst``
(``inst(1M)``): ``-f``/``-m``/``-r``/``-u``/``-F``/``-I``/``-R``/``-K``/
``-P``/``-V``/``-X``/``-Y``/``-c`` (valued) and ``-a -A -E -H -M -N -Q -n -C
-s -T -U -Z`` (flags).  Its shallow path is **byte-gated against the RE
oracle**: an unknown option, or a valued option with no value, prints
exactly ``Illegal option -- <ch>`` followed by the stock usage line and
exits 1 — the behavior recorded as byte-identical to the stock binary in
``progress_notes/binary_re/inst/FINDINGS.md`` (validated forms: ``-ZZbogus``,
``-?``, ``-X``).

**Documented extensions** — long options the stock binary has no concept of
(``--list``, ``--plan``, ``--plan-file``, ``--version``, ``--help``).  They
carry the M1 non-interactive face (media listing, dry-run plan JSON) and are
the CI/scripting entry points; the curses TTY UI (M2) and the real install
(M3) will grow off them.  A long option the port does not know is a port
error (stderr, exit 2), never "Illegal option" — that string is reserved for
the stock surface.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pyirix.inst import __version__
from pyirix.inst.media import DistError, MediaSource
from pyirix.inst.plan import build_plan

# The stock usage line, byte-for-byte from the RE oracle's validated shallow
# path (binary_re/inst/FINDINGS.md).  Do not reflow.
USAGE = (
    "usage: inst [ -anAENQ ] [ -f source ] [ -m hardware=value ] "
    "[ -r target ] [ -u action ] [ -F selections-file ] [ -I product ] "
    "[ -R product ] [ -K product ] [ -P file ] [ -V preference:value ]"
)

_VERSION_LINE = f"inst {__version__} (Linux port, M1 — dry-run only)"

# Stock option surface (inst(1M) SYNOPSIS + manpage option list).
_VALUED = {
    "f",  # source (repeatable)
    "m",  # hardware=value
    "r",  # target
    "u",  # action
    "F",  # selections-file
    "c",  # command-file
    "I",  # selection
    "R",  # selection
    "K",  # selection
    "P",  # file
    "V",  # preference:value
    "X",  # file
    "Y",  # file
}
_FLAGS = {"a", "A", "E", "H", "M", "N", "Q", "n", "C", "s", "T", "U", "Z"}

# Documented extensions (long options only).
_EXT_ACTIONS = {"--list", "--plan"}


def _illegal(char: str) -> int:
    """Print the stock illegal-option output (byte-gated) and return 1."""
    sys.stdout.write(f"Illegal option -- {char}\n{USAGE}\n")
    sys.stdout.flush()
    return 1


class _State:
    def __init__(self) -> None:
        self.sources: list[str] = []
        self.r_target: str | None = None
        self.u_action: str | None = None
        self.selections: list[str] = []
        self.preferences: list[str] = []
        self.dryrun = False
        self.flags: set[str] = set()
        self.extension: str | None = None
        self.plan_file: str | None = None


def _parse(argv: list[str]) -> tuple[_State, int | None]:
    """Parse argv against the stock surface.

    Returns (state, rc): rc is non-None when parsing terminated with the
    stock illegal-option output (already printed).
    """
    state = _State()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--") and len(arg) > 2:
            # Documented extension (or a port error) — never the stock
            # single-character surface.
            key, _, val = arg.partition("=")
            if key in _EXT_ACTIONS:
                if state.extension is not None:
                    sys.stderr.write(f"inst: one of --list/--plan per invocation (got {state.extension}, {key})\n")
                    return state, 2
                state.extension = key
            elif key == "--plan-file":
                if not val:
                    # Space form: --plan-file PATH
                    if i + 1 >= len(argv):
                        sys.stderr.write("inst: --plan-file requires a path\n")
                        return state, 2
                    val = argv[i + 1]
                    i += 1
                state.plan_file = val
            elif key == "--version":
                sys.stdout.write(_VERSION_LINE + "\n")
                return state, 0
            elif key == "--help":
                sys.stdout.write(USAGE + "\n")
                sys.stdout.write(
                    "long options (port extensions): --list, --plan, "
                    "--plan-file PATH, --version, --help\n"
                )
                return state, 0
            else:
                sys.stderr.write(f"inst: unknown option {key}\n")
                return state, 2
            i += 1
            continue

        if arg.startswith("-") and len(arg) > 1:
            for pos, ch in enumerate(arg[1:]):
                if ch in _VALUED:
                    # An inline value starts after the option character
                    # (arg[0] is '-', ch sits at arg[pos+1]).
                    rest = arg[pos + 2 :]
                    if rest:
                        value = rest
                        break
                    if i + 1 >= len(argv):
                        # Stock behavior: a valued option without a value is
                        # itself the illegal option (oracle: `inst -X`).
                        return state, _illegal(ch)
                    value = argv[i + 1]
                    i += 1
                    break
                if ch in _FLAGS:
                    if ch == "n":
                        state.dryrun = True
                    state.flags.add(ch)
                    continue
                return state, _illegal(ch)
            else:
                i += 1
                continue
            # A valued option: record it.
            if ch == "f":
                state.sources.append(value)
            elif ch == "r":
                state.r_target = value
            elif ch == "u":
                state.u_action = value
            elif ch in ("I", "R", "K"):
                state.selections.append(value)
            elif ch == "V":
                state.preferences.append(value)
            # -m/-F/-c/-P/-X/-Y: accepted on the stock surface, no M1 action.
            i += 1
            continue

        # Positional: stock has none; treat as illegal source?  Stock would
        # take the interactive path — M1 reports and declines (exit 2).
        sys.stderr.write(f"inst: unexpected argument {arg!r} (M1: no interactive mode)\n")
        return state, 2
    i += 1
    return state, None


def _print_list(media: MediaSource, selections: list[str]) -> None:
    prods = media.products
    if selections:
        wanted = set(selections)
        prods = [p for p in prods if p.name in wanted]
    for prod in prods:
        spec = "spec" if prod.has_spec else "nospec"
        subs = ", ".join(prod.subsystems[:6])
        if len(prod.subsystems) > 6:
            subs += "…"
        sys.stdout.write(
            f"{prod.name:40s} {prod.file_count:8d} files {prod.total_size():12d} bytes "
            f"[{spec}] {subs}\n"
        )
    sys.stdout.write(
        f"{len(prods)} products in {media.dist_dir}\n"
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns the process exit code."""
    if argv is None:
        argv = sys.argv[1:]
    state, rc = _parse(list(argv))
    if rc is not None:
        return rc

    sources = state.sources or [str(Path("."))]
    if len(sources) > 1:
        # Stock permits multiple -f; M1 installs from one distribution at a
        # time (multi-dist sequencing is an M2/M3 concern).
        sys.stderr.write("inst (M1): one -f source per invocation\n")
        return 2

    try:
        media = MediaSource(sources[0])
    except DistError as exc:
        sys.stderr.write(f"inst: {exc}\n")
        return 1

    if state.extension == "--list":
        _print_list(media, state.selections)
        return 0

    if state.extension == "--plan" or state.u_action == "plan":
        try:
            plan = build_plan(
                media,
                target=state.r_target or "tree",
                products=state.selections or None,
            )
        except ValueError as exc:
            sys.stderr.write(f"inst: {exc}\n")
            return 1
        if state.plan_file:
            plan.save(state.plan_file)
            sys.stdout.write(f"plan saved to {state.plan_file} "
                             f"({plan.total_files} files, {plan.total_bytes} bytes)\n")
        else:
            sys.stdout.write(plan.to_json() + "\n")
        return 0

    if state.u_action in ("install", "all") or "A" in state.flags:
        sys.stderr.write(
            "inst: install not implemented yet (M3: LinuxTarget; M2: TreeTarget + TTY UI)\n"
        )
        return 2

    # No action: stock would start the interactive TTY UI.  M1 reports.
    sys.stdout.write(
        f"{_VERSION_LINE}\n"
        f"source: {media.dist_dir} ({len(media.products)} products)\n"
        "interactive installation arrives in M2 (curses TTY UI); use\n"
        "  --list   to enumerate products, or\n"
        "  --plan   to print the dry-run install plan as JSON\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
