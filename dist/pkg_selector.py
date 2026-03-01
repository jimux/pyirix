#!/usr/bin/env python3
"""Interactive TUI for IRIX package family selection and resolution.

Uses Python curses (stdlib) for maximum portability — works on IRIX with
Python 3.6+, Linux, macOS, and any Unix terminal.

Usage:
    python3 -m pyirix.dist.pkg_selector
    python3 -m pyirix.dist.pkg_selector --platform o2
    python3 -m pyirix.dist.pkg_selector --no-color
"""

import argparse
import curses
import os
from pathlib import Path

from pyirix.dist.pkg_analyzer import (
    PLATFORMS, IRIX_VCODE_COMPAT, PRODUCT_FAMILIES, FAMILY_CATEGORIES,
    FamilyResolver, PackageDatabase, ResolveResult, extract_overlay_version,
)


# ── View state ───────────────────────────────────────────────────

class SelectorState:
    """Tracks UI state for the package selector."""

    # Screens
    SCREEN_SELECT = 0
    SCREEN_RESOLVE = 1

    def __init__(self, platform="indy", target="6.5"):
        self.platform = platform
        self.target = target
        self.screen = self.SCREEN_SELECT

        # Build ordered list of selectable families
        self.items = []      # [(category_header, None) | (family_key, family)]
        self.selected = {}   # family_key -> bool
        self.cursor = 0
        self.scroll_offset = 0

        self._build_items()

        # Resolve result (computed on demand)
        self.result = None    # type: ResolveResult
        self.result_scroll = 0

    def _build_items(self):
        """Build the display list grouped by category."""
        self.items = []
        for cat_key, cat_label in FAMILY_CATEGORIES:
            families_in_cat = [(k, f) for k, f in PRODUCT_FAMILIES.items()
                               if f.category == cat_key]
            if not families_in_cat:
                continue
            # Category header
            self.items.append((cat_label, None))
            for key, fam in families_in_cat:
                self.items.append((key, fam))
                if key not in self.selected:
                    self.selected[key] = fam.base  # base families pre-selected

        # Position cursor on first selectable item
        for i, (key, fam) in enumerate(self.items):
            if fam is not None and not fam.base:
                self.cursor = i
                break

    @property
    def platform_info(self):
        return PLATFORMS[self.platform]

    def selected_keys(self):
        """Return list of explicitly selected (non-base) family keys."""
        return [k for k, v in self.selected.items()
                if v and not PRODUCT_FAMILIES[k].base]

    def all_selected_keys(self):
        """Return all selected keys including base."""
        return [k for k, v in self.selected.items() if v]

    def toggle_current(self):
        """Toggle selection of item at cursor."""
        if self.cursor < 0 or self.cursor >= len(self.items):
            return
        key, fam = self.items[self.cursor]
        if fam is None:
            return  # header
        if fam.base:
            return  # can't deselect base
        self.selected[key] = not self.selected.get(key, False)

        # Auto-select dependencies when selecting
        if self.selected[key]:
            self._auto_select_deps(key)

    def _auto_select_deps(self, key):
        """Recursively select dependencies of a family."""
        fam = PRODUCT_FAMILIES.get(key)
        if not fam:
            return
        for dep in fam.implicit_deps:
            if dep in self.selected and not self.selected[dep]:
                dep_fam = PRODUCT_FAMILIES.get(dep)
                if dep_fam and not dep_fam.base:
                    self.selected[dep] = True
                    self._auto_select_deps(dep)

    def cycle_platform(self, direction=1):
        """Cycle through available platforms."""
        platforms = sorted(PLATFORMS.keys())
        idx = platforms.index(self.platform)
        idx = (idx + direction) % len(platforms)
        self.platform = platforms[idx]
        self.result = None  # invalidate

    def move_cursor(self, delta):
        """Move cursor, skipping headers."""
        new_pos = self.cursor + delta
        # Clamp
        new_pos = max(0, min(len(self.items) - 1, new_pos))
        # Skip headers in the direction of movement
        while 0 <= new_pos < len(self.items):
            key, fam = self.items[new_pos]
            if fam is not None:
                break
            new_pos += (1 if delta > 0 else -1)
        if 0 <= new_pos < len(self.items):
            self.cursor = new_pos


# ── Drawing ──────────────────────────────────────────────────────

def _init_colors():
    """Initialize color pairs if terminal supports color."""
    if not curses.has_colors():
        return False
    curses.start_color()
    curses.use_default_colors()
    # pair 1: header (cyan)
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    # pair 2: selected item (green)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    # pair 3: cursor highlight (reverse)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
    # pair 4: base/locked (dim yellow)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    # pair 5: status bar
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE)
    # pair 6: error/unresolved (red)
    curses.init_pair(6, curses.COLOR_RED, -1)
    # pair 7: description (dim)
    curses.init_pair(7, curses.COLOR_WHITE, -1)
    return True


def draw_select_screen(stdscr, state, has_color):
    """Draw the family selection screen."""
    height, width = stdscr.getmaxyx()
    if height < 10 or width < 40:
        stdscr.addstr(0, 0, "Terminal too small (need 40x10)")
        return

    # Title bar
    title = " IRIX Package Selector "
    plat_str = "%s | %s" % (state.platform_info["name"],
                            state.platform_info["max_overlay"])
    header = title.ljust(width - len(plat_str) - 1) + plat_str
    header = header[:width - 1]
    if has_color:
        stdscr.attron(curses.color_pair(5))
    stdscr.addstr(0, 0, header.ljust(width - 1))
    if has_color:
        stdscr.attroff(curses.color_pair(5))

    # Count selected
    n_sel = len(state.selected_keys())

    # Scrollable list area
    list_top = 2
    list_bottom = height - 3  # leave room for status bar + help
    visible_lines = list_bottom - list_top

    # Adjust scroll to keep cursor visible
    if state.cursor < state.scroll_offset:
        state.scroll_offset = state.cursor
    elif state.cursor >= state.scroll_offset + visible_lines:
        state.scroll_offset = state.cursor - visible_lines + 1

    for row in range(visible_lines):
        item_idx = state.scroll_offset + row
        y = list_top + row
        if y >= height - 2:
            break
        if item_idx >= len(state.items):
            break

        key, fam = state.items[item_idx]
        is_cursor = (item_idx == state.cursor)

        if fam is None:
            # Category header
            label = "  %s:" % key
            attr = curses.color_pair(1) | curses.A_BOLD if has_color else curses.A_BOLD
            if is_cursor:
                attr = curses.color_pair(3) if has_color else curses.A_REVERSE
            _safe_addstr(stdscr, y, 0, label.ljust(width - 1)[:width - 1], attr)
        else:
            # Selectable family
            is_sel = state.selected.get(key, False)
            is_base = fam.base

            if is_base:
                marker = "[=]"  # locked
            elif is_sel:
                marker = "[x]"
            else:
                marker = "[ ]"

            deps_str = ""
            if fam.implicit_deps:
                deps_str = "  -> %s" % ", ".join(fam.implicit_deps)

            label = "    %s %-14s %-22s%s" % (marker, key, fam.name,
                                               deps_str)
            label = label[:width - 1]

            if is_cursor:
                attr = curses.color_pair(3) if has_color else curses.A_REVERSE
            elif is_base:
                attr = curses.color_pair(4) if has_color else curses.A_DIM
            elif is_sel:
                attr = curses.color_pair(2) if has_color else curses.A_BOLD
            else:
                attr = 0

            _safe_addstr(stdscr, y, 0, label.ljust(width - 1)[:width - 1], attr)

    # Description line (show for current item)
    desc_y = height - 3
    key, fam = state.items[state.cursor] if state.cursor < len(state.items) else ("", None)
    if fam and fam.description:
        desc = fam.description[:width - 3]
        attr = curses.color_pair(7) | curses.A_DIM if has_color else curses.A_DIM
        _safe_addstr(stdscr, desc_y, 1, desc, attr)

    # Status / help bar
    status_y = height - 2
    help_y = height - 1
    status = " %d families selected | Platform: %s (P to change)" % (
        n_sel, state.platform)
    if has_color:
        stdscr.attron(curses.color_pair(5))
    _safe_addstr(stdscr, status_y, 0, status.ljust(width - 1)[:width - 1])
    if has_color:
        stdscr.attroff(curses.color_pair(5))

    help_text = " SPACE=toggle  ENTER=resolve  A=all  N=none  P=platform  Q=quit"
    _safe_addstr(stdscr, help_y, 0, help_text[:width - 1])


def draw_resolve_screen(stdscr, state, has_color):
    """Draw the resolution results screen."""
    height, width = stdscr.getmaxyx()
    result = state.result

    # Title bar
    title = " Resolution Results "
    plat_str = "%s | IRIX %s" % (state.platform_info["name"], state.target)
    header = title.ljust(width - len(plat_str) - 1) + plat_str
    if has_color:
        stdscr.attron(curses.color_pair(5))
    _safe_addstr(stdscr, 0, 0, header.ljust(width - 1)[:width - 1])
    if has_color:
        stdscr.attroff(curses.color_pair(5))

    if result is None:
        _safe_addstr(stdscr, 2, 2, "No resolution computed.")
        _safe_addstr(stdscr, height - 1, 0, " ESC=back  Q=quit")
        return

    # Build result text lines
    lines = []
    lines.append("")

    # Families
    user = state.selected_keys()
    auto = [k for k in result.expanded_families if k not in user
            and not PRODUCT_FAMILIES.get(k, ProductFamilyStub()).base]
    lines.append("Families: %s" % ", ".join(user))
    if auto:
        lines.append("  (auto-added: %s)" % ", ".join(auto))
    lines.append("")

    # Products
    lines.append("Required products (%d):" % len(result.required_products))
    prod_line = "  " + ", ".join(sorted(result.required_products))
    # Word-wrap product list
    while len(prod_line) > width - 2:
        cut = prod_line.rfind(", ", 0, width - 4)
        if cut < 0:
            cut = width - 4
        lines.append(prod_line[:cut + 1])
        prod_line = "  " + prod_line[cut + 2:]
    lines.append(prod_line)
    lines.append("")

    # Selected images
    if result.selected_images:
        lines.append("Required CD Images (%d):" % len(result.selected_images))
        for md5, filename, prods in result.selected_images:
            ov = extract_overlay_version(filename)
            tag = " (overlay)" if ov else ""
            line = "  %s  %-50s %2d products%s" % (
                md5[:8], filename[:50], len(prods), tag)
            lines.append(line)
            # Show covered products indented
            prod_str = "           %s" % ", ".join(prods)
            while len(prod_str) > width - 2:
                cut = prod_str.rfind(", ", 0, width - 4)
                if cut < 0:
                    cut = width - 4
                lines.append(prod_str[:cut + 1])
                prod_str = "           " + prod_str[cut + 2:]
            lines.append(prod_str)
    else:
        lines.append("No CD images needed.")

    lines.append("")

    # Unresolved
    if result.unresolved_products:
        lines.append("UNRESOLVED (%d):" % len(result.unresolved_products))
        lines.append("  %s" % ", ".join(result.unresolved_products))
        lines.append("")

    # Warnings
    if result.warnings:
        for w in result.warnings:
            lines.append("  WARNING: %s" % w)
        lines.append("")

    # Summary
    if result.total_size:
        size_mb = result.total_size / (1024 * 1024)
        lines.append("Total: %d images, %.0f MB" % (
            len(result.selected_images), size_mb))
    else:
        lines.append("Total: %d images" % len(result.selected_images))

    # Scrollable display
    list_top = 1
    list_bottom = height - 2
    visible = list_bottom - list_top

    # Adjust scroll
    max_scroll = max(0, len(lines) - visible)
    state.result_scroll = max(0, min(state.result_scroll, max_scroll))

    for row in range(visible):
        line_idx = state.result_scroll + row
        y = list_top + row
        if line_idx >= len(lines):
            break

        text = lines[line_idx][:width - 1]

        attr = 0
        if has_color:
            if text.strip().startswith("UNRESOLVED"):
                attr = curses.color_pair(6) | curses.A_BOLD
            elif text.strip().startswith("WARNING"):
                attr = curses.color_pair(4)
            elif text.strip().startswith("Required CD"):
                attr = curses.color_pair(2) | curses.A_BOLD
            elif text.strip().startswith("Families:"):
                attr = curses.color_pair(1)
            elif text.strip().startswith("Total:"):
                attr = curses.A_BOLD
            elif len(text) > 2 and text[2:10].replace(' ', '').isalnum() and '  ' in text[2:15]:
                # Image line (hash prefix)
                attr = curses.color_pair(2)

        _safe_addstr(stdscr, y, 0, text, attr)

    # Scroll indicator
    if max_scroll > 0:
        pct = int(100 * state.result_scroll / max_scroll) if max_scroll else 0
        scroll_str = " [%d%%]" % pct
        _safe_addstr(stdscr, 0, width - len(scroll_str) - 1, scroll_str,
                     curses.color_pair(5) if has_color else 0)

    # Help bar
    help_text = " ESC=back  UP/DOWN=scroll  Q=quit"
    _safe_addstr(stdscr, height - 1, 0, help_text[:width - 1])


def _safe_addstr(win, y, x, text, attr=0):
    """Write string, silently handling curses boundary errors."""
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


class ProductFamilyStub:
    """Fallback for missing family lookups."""
    base = False


# ── Main loop ────────────────────────────────────────────────────

def run_tui(stdscr, state, use_color):
    """Main curses event loop."""
    curses.curs_set(0)  # hide cursor
    stdscr.timeout(-1)  # blocking getch
    has_color = use_color and _init_colors()

    db = None

    while True:
        stdscr.erase()

        if state.screen == SelectorState.SCREEN_SELECT:
            draw_select_screen(stdscr, state, has_color)
        elif state.screen == SelectorState.SCREEN_RESOLVE:
            draw_resolve_screen(stdscr, state, has_color)

        stdscr.refresh()
        ch = stdscr.getch()

        if state.screen == SelectorState.SCREEN_SELECT:
            if ch == ord('q') or ch == ord('Q'):
                break
            elif ch == curses.KEY_UP or ch == ord('k'):
                state.move_cursor(-1)
            elif ch == curses.KEY_DOWN or ch == ord('j'):
                state.move_cursor(1)
            elif ch == curses.KEY_PPAGE:
                state.move_cursor(-10)
            elif ch == curses.KEY_NPAGE:
                state.move_cursor(10)
            elif ch == ord(' '):
                state.toggle_current()
            elif ch == ord('\n') or ch == curses.KEY_ENTER or ch == 13:
                # Resolve
                stdscr.erase()
                _safe_addstr(stdscr, stdscr.getmaxyx()[0] // 2,
                             2, "Resolving dependencies...")
                stdscr.refresh()
                if db is None:
                    db = PackageDatabase()
                try:
                    resolver = FamilyResolver(db, target_version=state.target,
                                              platform=state.platform)
                    keys = state.all_selected_keys()
                    state.result = resolver.resolve(keys)
                except Exception as e:
                    state.result = None
                    state.result = ResolveResult(
                        expanded_families=[],
                        required_products=set(),
                        selected_images=[],
                        unresolved_products=["ERROR: %s" % str(e)],
                    )
                state.result_scroll = 0
                state.screen = SelectorState.SCREEN_RESOLVE
            elif ch == ord('p') or ch == ord('P'):
                state.cycle_platform()
            elif ch == ord('a') or ch == ord('A'):
                # Select all non-base
                for k, f in PRODUCT_FAMILIES.items():
                    if not f.base:
                        state.selected[k] = True
            elif ch == ord('n') or ch == ord('N'):
                # Deselect all non-base
                for k, f in PRODUCT_FAMILIES.items():
                    if not f.base:
                        state.selected[k] = False

        elif state.screen == SelectorState.SCREEN_RESOLVE:
            if ch == 27 or ch == curses.KEY_BACKSPACE or ch == 127:
                # ESC or backspace -> back to select
                state.screen = SelectorState.SCREEN_SELECT
            elif ch == ord('q') or ch == ord('Q'):
                break
            elif ch == curses.KEY_UP or ch == ord('k'):
                state.result_scroll = max(0, state.result_scroll - 1)
            elif ch == curses.KEY_DOWN or ch == ord('j'):
                state.result_scroll += 1
            elif ch == curses.KEY_PPAGE:
                state.result_scroll = max(0, state.result_scroll - 10)
            elif ch == curses.KEY_NPAGE:
                state.result_scroll += 10

    if db is not None:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Interactive IRIX package family selector (curses TUI)")
    parser.add_argument('--platform', default='indy',
                        choices=sorted(PLATFORMS.keys()),
                        help='Initial platform (default: indy)')
    parser.add_argument('--target', default='6.5',
                        choices=sorted(IRIX_VCODE_COMPAT.keys()),
                        help='Target IRIX version (default: 6.5)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable color output')
    args = parser.parse_args()

    state = SelectorState(platform=args.platform, target=args.target)
    use_color = not args.no_color

    try:
        curses.wrapper(lambda stdscr: run_tui(stdscr, state, use_color))
    except KeyboardInterrupt:
        pass

    # Print final selection to stdout for scripting
    selected = state.selected_keys()
    if selected:
        print("Selected families: %s" % " ".join(selected))
        if state.result and state.result.selected_images:
            print("\nResolved CD images:")
            for md5, filename, prods in state.result.selected_images:
                print("  %s  %s" % (md5[:8], filename))


if __name__ == '__main__':
    main()
