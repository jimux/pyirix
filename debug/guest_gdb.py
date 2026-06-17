"""guest_gdb — drive gdb-multiarch against the QEMU guest MIPS64 kernel.

QEMU's gdbstub is fully wired; launch a session with extra_args="-gdb tcp::PORT"
and this connects gdb-multiarch to the live kernel, sets (hardware) breakpoints
at kernel VAs, runs the guest until a breakpoint hits (e.g. `panic`), and dumps
the full register state + a stack scan for return addresses + symbolized PCs.

Symbols come from the disk-kernel JSON (ip54_kernel_symbols_disk.json) — the
running /unix.new — NOT from irix_unix.elf (a different build).  gdb breakpoints
use raw addresses; symbolization is done here in Python.

Typical use (the guest must already be booted+logged-in and about to crash):

    g = GuestGDB(port=1234)
    out = g.catch(breakpoints=["panic"], timeout=120)   # blocks until hit
    print(g.symbolize_dump(out))
"""
import json
import bisect
import subprocess

# WARNING: ip54_kernel_symbols_disk.json is STALE vs the golden kernel — every
# address is off (splx, idev*, qcntl* all wrong), which makes gdb breakpoints
# silently hit WRONG addresses.  ip54_kernel_symbols_golden.json is regenerated
# from the actual golden /unix (gen_golden_syms.py).  When the kernel is rebuilt,
# regenerate it.  See memory kernel_symbol_drift.
SYMS_JSON = "/workspace/ip54_kernel_symbols_golden.json"


class SymbolDB:
    """Cached kernel symbol service: name->addr, addr->name+offset."""
    _cache = {}

    def __init__(self, path=SYMS_JSON):
        if path not in SymbolDB._cache:
            d = json.load(open(path))
            funcs = sorted((s["address"] & 0xffffffff, s["name"])
                           for s in d if s.get("type") == "FUNC")
            byname = {s["name"]: (s["address"] & 0xffffffff) for s in d}
            addrs = [a for a, _ in funcs]
            # Derive the kernel-text range from the symbols themselves rather
            # than hardcoding 0x88300000 (too narrow for padded/stripped builds).
            text_lo = addrs[0] if addrs else 0x88000000
            text_hi = (addrs[-1] + 0x20000) if addrs else 0x88300000
            SymbolDB._cache[path] = (funcs, addrs, byname, text_lo, text_hi)
        (self.funcs, self.addrs, self.byname,
         self.text_lo, self.text_hi) = SymbolDB._cache[path]

    def addr(self, name):
        a = self.byname.get(name)
        if a is None:
            raise KeyError(f"symbol not found: {name}")
        return a

    def lookup(self, addr):
        a = addr & 0xffffffff
        i = bisect.bisect_right(self.addrs, a) - 1
        if i < 0:
            return None
        name, base = self.funcs[i][1], self.funcs[i][0]
        return f"{name}+0x{a - base:x}"

    def is_kernel_text(self, addr):
        a = addr & 0xffffffff
        return self.text_lo <= a <= self.text_hi


class GuestGDB:
    def __init__(self, port=1234, syms=SYMS_JSON, replay=False, kernel_elf=None):
        """port: gdbstub TCP port.  replay: True if the QEMU session was started
        with rr=replay (enables reverse-* commands; see replay_debugging_ip54).
        kernel_elf: path to a kernel ELF whose symbols are loaded INTO gdb via
        add-symbol-file, so backtraces/`info symbol` resolve names natively."""
        self.port = port
        self.sdb = SymbolDB(syms)
        self.replay = replay
        self.kernel_elf = kernel_elf

    @staticmethod
    def _sx(addr):
        """Sign-extend a 32-bit KSEG VA to the 64-bit form the n64 ABI expects:
        0x881a34b4 -> 0xffffffff881a34b4.  Leaves already-64-bit values alone."""
        a = addr & 0xffffffffffffffff
        if a < 0x100000000 and (a & 0x80000000):
            a |= 0xffffffff00000000
        return a

    def _resolve(self, bp):
        """Accept a symbol name or a hex/int address; return a gdb break spec.
        Kernel addresses are sign-extended (n64 ABI) so the bp matches $pc."""
        if isinstance(bp, int):
            return f"*0x{self._sx(bp):x}"
        if bp.startswith("0x"):
            return f"*0x{self._sx(int(bp, 16)):x}"
        return f"*0x{self._sx(self.sdb.addr(bp)):x}"

    def _resolve_data(self, expr):
        """Build a gdb watchpoint target for a 32-bit kernel word.  Accepts an
        int/hex address or a data-symbol name; returns `*(unsigned int *)0xVA`
        with the VA sign-extended for the n64 ABI."""
        if isinstance(expr, int):
            va = self._sx(expr)
        elif expr.startswith("0x"):
            va = self._sx(int(expr, 16))
        else:
            va = self._sx(self.sdb.addr(expr))
        return f"*(unsigned int *)0x{va:x}"

    def _preamble(self, connect=True):
        """The standard n64/big-endian gdb setup (see `set mips abi n64` note in
        catch()).  Loads kernel ELF symbols if kernel_elf was given."""
        cmds = [
            "set pagination off",
            "set confirm off",
            "set architecture mips:isa64",
            "set mips abi n64",
            "set endian big",
        ]
        if self.kernel_elf:
            # .text of the disk kernel lives at KSEG0 0x88000000 (sign-extended).
            cmds.append(
                f"add-symbol-file {self.kernel_elf} 0x{self._sx(0x88000000):x}")
        if connect:
            cmds.append(f"target remote :{self.port}")
        return cmds

    _STOP_DUMP = [
        'echo \\n==== STOPPED ====\\n',
        "info registers",
        'echo \\n==== code at $pc ====\\n',
        "x/8i $pc",
    ]

    def _run(self, cmds, timeout=120, cmdfile="/workspace/_gdb_run.txt"):
        """Write cmds to a batch file and run gdb-multiarch, tolerating a
        timeout (a blocked `continue`)."""
        cmds = list(cmds) + ["detach", "quit", ""]
        with open(cmdfile, "w") as f:
            f.write("\n".join(cmds))
        try:
            r = subprocess.run(["gdb-multiarch", "-nx", "-batch", "-x", cmdfile],
                               capture_output=True, text=True, timeout=timeout)
            out, err = r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            out += "\n[GDB TIMEOUT after %ds]" % timeout
        return out + ("\n[GDB STDERR]\n" + err if err.strip() else "")

    def catch(self, breakpoints, timeout=180, post_cmds=None, cmdfile="/workspace/_gdb_catch.txt"):
        """Connect, set hbreak(s), continue (blocks until a bp hits or timeout),
        then dump registers + a stack scan.  Returns gdb's stdout."""
        # gdb's MIPS pointer width follows the ABI, not the ISA: the default
        # o32/n32 ABI keeps addresses 32-bit, so gdb zero-extends KSEG0 VAs into
        # unmapped xkphys ("Cannot access memory") and breakpoint planting (a
        # memory write) silently fails.  _preamble() sets `mips abi n64`.
        cmds = self._preamble()
        for bp in breakpoints:
            cmds.append(f"hbreak {self._resolve(bp)}")
        cmds.append("continue")
        # On breakpoint hit (or async stop), dump everything useful:
        cmds += [
            'echo \\n==== STOPPED ====\\n',
            "info registers",
            'echo \\n==== STACK (256 words from $sp) ====\\n',
            "x/256xw $sp",
            'echo \\n==== code at $pc ====\\n',
            "x/8i $pc",
        ]
        cmds += (post_cmds or [])
        cmds += ["detach", "quit", ""]
        with open(cmdfile, "w") as f:
            f.write("\n".join(cmds))
        try:
            r = subprocess.run(["gdb-multiarch", "-nx", "-batch", "-x", cmdfile],
                               capture_output=True, text=True, timeout=timeout)
            out, err = r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            # gdb's `continue` blocked (no breakpoint hit within timeout).
            out = (e.stdout or b"")
            err = (e.stderr or b"")
            out = out.decode() if isinstance(out, bytes) else (out or "")
            err = err.decode() if isinstance(err, bytes) else (err or "")
            out += "\n[GDB TIMEOUT — breakpoint not hit within %ds]" % timeout
        return out + ("\n[GDB STDERR]\n" + err if err.strip() else "")

    def read_word(self, addr, timeout=30, cmdfile="/workspace/_gdb_rw.txt"):
        """One-shot: connect, read a 32-bit word, detach (does NOT stop a
        running guest for long)."""
        cmds = self._preamble() + [
            f"x/1xw 0x{addr & 0xffffffffffffffff:x}",
            "detach", "quit", "",
        ]
        with open(cmdfile, "w") as f:
            f.write("\n".join(cmds))
        r = subprocess.run(["gdb-multiarch", "-nx", "-batch", "-x", cmdfile],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout

    def watch(self, expr, kind="w", timeout=180, post_cmds=None):
        """Set a HARDWARE watchpoint on a 32-bit kernel word and continue until
        it triggers, then dump registers + code at $pc.

        kind: 'w' write (watch), 'r' read (rwatch), 'a' access (awatch).
        The gdbstub plants these via the Z2/Z3/Z4 packets.

        KNOWN LIMITATION (validated 2026-06-12 on this sgi-ip54 build): gdb
        hardware watchpoints PLANT but never FIRE here — even on `lbolt`, which
        the kernel writes 100Hz.  Kernel data lives in MIPS KSEG0/KSEG1
        (unmapped, direct-mapped) and this QEMU's TCG watchpoint check does not
        appear to cover those accesses.  Breakpoints (catch) and reverse-stepi
        DO work.  For reliable "trap any write to phys addr X" use a TCG memory
        plugin (qemu_plugin_register_vcpu_mem_cb; CONFIG_PLUGIN is enabled), or
        reverse-debug from the corrupted state.  This method is kept for the day
        the QEMU watchpoint path is fixed.  See [[replay_debugging_ip54]]."""
        verb = {"w": "watch", "r": "rwatch", "a": "awatch"}[kind]
        cmds = self._preamble()
        cmds.append(f"{verb} {self._resolve_data(expr)}")
        cmds.append("continue")
        cmds += self._STOP_DUMP
        cmds += (post_cmds or [])
        return self._run(cmds, timeout=timeout, cmdfile="/workspace/_gdb_watch.txt")

    def catch_if(self, bp, condition, timeout=180, post_cmds=None):
        """Conditional breakpoint: stop at `bp` only when `condition` holds
        (e.g. catch_if("schedule", "$a0 == 0")).  Uses a soft breakpoint so the
        condition can be evaluated; hbreak doesn't take conditions on all stubs."""
        cmds = self._preamble()
        cmds.append(f"break {self._resolve(bp)} if {condition}")
        cmds.append("continue")
        cmds += self._STOP_DUMP
        cmds += (post_cmds or [])
        return self._run(cmds, timeout=timeout, cmdfile="/workspace/_gdb_condbp.txt")

    def script(self, body, timeout=180, cmdfile="/workspace/_gdb_script.txt"):
        """Escape hatch: run an arbitrary list of gdb commands after the standard
        n64 preamble (connect + symbols).  Use for composed reverse-debugging,
        e.g. body=["break panic","continue", ...,"reverse-continue","bt"]."""
        return self._run(self._preamble() + list(body), timeout=timeout,
                         cmdfile=cmdfile)

    def reverse_step(self, n=1):
        """Reverse-execute n instructions.  Requires a replay-mode session.
        Returns the gdb command strings for composition in script(); raises if
        this session isn't a replay session."""
        self._require_replay("reverse_step")
        return [f"reverse-stepi {n}", "info registers pc"]

    def reverse_continue(self):
        """Run backward to the most recent prior breakpoint/watchpoint hit
        (replay only).  Returns gdb command strings for use in script()."""
        self._require_replay("reverse_continue")
        return ["reverse-continue", "info registers pc"]

    def _require_replay(self, what):
        if not self.replay:
            raise RuntimeError(
                f"{what} requires a replay-mode session (start QEMU with "
                f"rr=replay,rrsnapshot=... and pass replay=True).  gdb's "
                f"reverse-* commands only work against a replaying QEMU.")

    def symbolize_dump(self, out):
        """Post-process a catch() dump: annotate every kseg0 word in the stack
        scan with its symbol (return-address candidates), and the PC."""
        import re
        lines = out.splitlines()
        result = []
        for ln in lines:
            result.append(ln)
            # stack words: lines like "0xADDR:  0xWORD 0xWORD 0xWORD 0xWORD"
            words = re.findall(r"0x([0-9a-f]{8})\b", ln)
            syms = []
            for w in words:
                v = int(w, 16)
                if self.sdb.is_kernel_text(v):
                    s = self.sdb.lookup(v)
                    if s:
                        syms.append(f"{w}={s}")
            if syms and ":" in ln:  # a memory/x line
                result.append("        ^syms: " + "  ".join(syms))
        # also pull the pc line
        m = re.search(r"\bpc\s+0x([0-9a-f]+)", out)
        if m:
            result.append(f"\n### PC = {self.sdb.lookup(int(m.group(1), 16))}")
        return "\n".join(result)
