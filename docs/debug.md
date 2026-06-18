# `pyirix.debug` — IRIX Binary Analysis & Debugging

> Part of the [pyirix documentation](../README.md).

Two halves under one roof. The **static** tools analyze extracted ELF binaries with no QEMU — disassembly, symbol lookup, string/syscall/data references, call graphs, DWARF type recovery. The **live** tool (`guest_gdb`) drives `gdb-multiarch` against a running QEMU MIPS64 guest.

Every static module is runnable as a script: `python3 -m pyirix.debug.<module>`. Most share two environment variables for configuration — `KELF` (path to the kernel/ELF) and `KSYMS` (path to a symbol JSON) — with defaults pointing at the golden IP54 kernel.

## Shared symbol-resolution pattern

`strings`, `syscalls`, `xref`, `callgraph`, `dataref`, and `disasm` all parse ELF section headers from scratch (no pyelftools; ELF32/ELF64 auto-detected, big-endian assumed), load the symbol JSON, build a sorted `(addr, name)` list, and use `bisect` to resolve any PC to its enclosing function. The symbol JSON is produced by `syms.py` (below).

## Static tools

| Module | What it does | How |
|--------|--------------|-----|
| `dwarf` | DWARF2 type recovery | From-scratch parser for SGI MIPS_DWARF2 (`.debug_abbrev`/`.debug_info`); recovers structs, unions, functions, globals |
| `disasm` | Disassemble one function by name | Looks up symbol → file offset, runs the capstone wrapper, resolves `jal`/`j` targets to symbols |
| `mips_disasm` | Capstone MIPS64/BE engine | Annotates `lui+addiu`/`ori` address reconstruction with hardware register names; finds function prologues |
| `mipsasm` | Assemble MIPS → BE words | Wraps `mips-elf-as`/`objcopy`; emits hex, C arrays, or pointer-assignment trampolines |
| `strings` | Resolve string references | Tracks `lui`+`addiu`/`ori` register pairs, reads the pointed-at C string |
| `syscalls` | Inventory ioctl constants | Catches `lui+ori` immediates that decode as `_IO`-style ioctl command words |
| `xref` | Find callers of a function | Encodes the exact `jal <target>` word and byte-searches kernel text |
| `callgraph` | Whole-binary call graph | Scans every `jal`, builds callees/callers maps, supports BFS path queries |
| `dataref` | Find references to an address | Scans for the address as a stored data word, reports nearest object/function symbols |
| `syms` | Generate / drift-check symbol JSON | Parses `readelf -sW`; `drift` flags when a saved JSON diverges from the live kernel |
| `modules` | Partition a DWARF ELF into source modules | Uses `.debug_line` to map each function address back to its `.c` file |

### DWARF type recovery

```python
from pyirix.debug.dwarf import DwarfParser

dw = DwarfParser("/path/to/binary_with_dwarf")
for s in dw.structs():
    layout = dw.struct_layout(s)              # {name, kind, size, members:[{name, offset, type}]}
for fn in dw.funcs():                          # [{name, ret, params:[{name,type}]}]
    print(fn["name"], fn["ret"])
```

```bash
python3 -m pyirix.debug.dwarf <elf> struct <name>     # print one struct layout
python3 -m pyirix.debug.dwarf <elf> structs [substr]  # list structs
python3 -m pyirix.debug.dwarf <elf> func <name>       # C prototype
python3 -m pyirix.debug.dwarf <elf> vars [substr]     # globals by address
python3 -m pyirix.debug.dwarf <elf> json out.json     # dump structs + funcs
```

The SGI quirk this works around: SGI abbrev tables are **not** null-terminated and codes reset per compilation unit, so the parser stops when a code is `0` or `<=` the previous code rather than relying on a terminator.

### Disassembly and assembly

```bash
KELF=/path/unix KSYMS=/path/syms.json python3 -m pyirix.debug.disasm pvfb_gf_PositionCursor
```

```python
from pyirix.debug.mipsasm import assemble, emit_p_array
words = assemble("lui $t0, 0x1f48\naddiu $t0, $t0, 0x100\n")   # -> [0x..., 0x...]
print(emit_p_array(words, "trampoline"))      # trampoline[0] = 0x...U; ...
```

```bash
python3 -m pyirix.debug.mipsasm trampoline.s --c-array tramp     # or --p-array PTR, or raw hex
```

### Cross-references, strings, syscalls, call graph

```bash
KELF=… KSYMS=… python3 -m pyirix.debug.xref     idevGenPtrEvent   # who calls it
KELF=… KSYMS=… python3 -m pyirix.debug.strings  --func cmn_err    # string refs in a function
KELF=… KSYMS=… python3 -m pyirix.debug.syscalls --func qcntlpoll  # ioctl constants used
KELF=… KSYMS=… python3 -m pyirix.debug.callgraph build            # writes KCG json
KELF=… KSYMS=… python3 -m pyirix.debug.callgraph path splx schedule   # BFS call path
KELF=… KSYMS=… python3 -m pyirix.debug.dataref  0x88123456        # references to an address
```

### Keeping symbols honest

Kernel symbol JSONs drift from the golden `/unix`; regenerate before any gdb/symbol work.

```bash
python3 -m pyirix.debug.syms gen --elf /path/unix --out syms.json
python3 -m pyirix.debug.syms gen --image disk.qcow2 --kpath /unix --out syms.json
python3 -m pyirix.debug.syms drift --elf /path/unix --json syms.json   # exits 1 if >10% drifted
```

## Live debugging (`guest_gdb`)

`GuestGDB` writes a gdb command file and runs `gdb-multiarch -nx -batch` against the guest's gdbstub. The critical detail is the **preamble**: it sets `architecture mips:isa64`, `mips abi n64`, and `endian big`. Without the n64 ABI, gdb zero-extends 32-bit KSEG0 kernel addresses into unmapped xkphys space and breakpoint planting silently fails — `_sx()` sign-extends every address to the negative 64-bit form the ABI expects.

```python
from pyirix.debug.guest_gdb import GuestGDB

g = GuestGDB(port=1234, syms="ip54_kernel_symbols_golden.json")

# Hardware breakpoint by name; on stop, dumps registers + 256 stack words + code at $pc
out = g.catch(["pvfb_gf_PositionCursor"])
print(g.symbolize_dump(out))                  # annotate kernel-text words with symbols

print(g.read_word("vc2_cursor_x"))            # one-shot peek of a 32-bit kernel word
g.catch_if("idev_rput", "$a1 == 0")           # conditional (soft) breakpoint
```

`catch` uses hardware breakpoints (`hbreak`) so it never has to write the kernel text. `read_word` does a one-shot peek. `catch_if` plants a conditional soft breakpoint. A documented limitation: hardware **watchpoints** (`watch()`) plant but never fire on the sgi-ip54/TCG build because KSEG0/KSEG1 data is direct-mapped and TCG's watchpoint check doesn't cover those accesses — use replay/reverse-debugging to find a corrupting write instead.

Replay mode enables reverse execution. `reverse_step()` and `reverse_continue()` **return gdb command lists** (they don't run gdb themselves) for composition inside `script()`:

```python
g = GuestGDB(replay=True)                      # QEMU started with record/replay (rr=replay)
print(g.script(["break panic", "continue"] + g.reverse_step(50)))
```

`SymbolDB` (used internally, also usable directly) caches the parsed symbol JSON per path across instances, exposing `addr(name)`, `lookup(addr) -> "name+0xoff"`, and `is_kernel_text(addr)`.
