# `pyirix.debug` — IRIX Binary Analysis & Debugging

> Part of the [pyirix documentation](../README.md).

Two halves under one roof. The **static** tools analyze extracted ELF binaries with no QEMU — disassembly, symbol lookup, string/syscall/data references, call graphs, DWARF type recovery. The **live** tool (`guest_gdb`) drives `gdb-multiarch` against a running QEMU MIPS64 guest.

Every static module is runnable as a script: `python3 -m pyirix.debug.<module>`. Most share two environment variables for configuration — `KELF` (path to the kernel/ELF) and `KSYMS` (path to a symbol JSON) — with defaults pointing at the golden IP54 kernel.

## Shared symbol-resolution pattern

`strings`, `syscalls`, `xref`, `callgraph`, `dataref`, and `disasm` all parse ELF section headers from scratch (no pyelftools; ELF32/ELF64 auto-detected, big-endian assumed), load the symbol JSON, build a sorted `(addr, name)` list, and use `bisect` to resolve any PC to its enclosing function. The symbol JSON is produced by `syms.py` (below).

## Static tools

| Module | What it does | How |
|--------|--------------|-----|
| `dwarf` | DWARF2 type recovery | From-scratch parser for SGI MIPS_DWARF2 (`.debug_abbrev`/`.debug_info`); recovers structs, unions, functions, globals — with addresses, linkage names, and CU offsets |
| `dwarf_bias` | Per-CU address-bias recovery | Maps un-relocated DWARF `low_pc` values onto real binary addresses via exported-symbol anchors; classifies CUs zero-bias / biased / multi-section |
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
for fn in dw.funcs():                          # [{name, ret, params, low_pc, linkage, cu}]
    print(fn["name"], hex(fn["low_pc"] or 0))
for v in dw.variables():                       # [{name, type, addr, linkage, cu}]
    print(v["name"], hex(v["addr"] or 0))
```

```bash
python3 -m pyirix.debug.dwarf <elf> struct <name>     # print one struct layout
python3 -m pyirix.debug.dwarf <elf> structs [substr]  # list structs
python3 -m pyirix.debug.dwarf <elf> func <name>       # C prototype
python3 -m pyirix.debug.dwarf <elf> vars [substr]     # globals by address
python3 -m pyirix.debug.dwarf <elf> json out.json     # dump structs + funcs + vars
```

The SGI quirk this works around: SGI abbrev tables are **not** null-terminated and codes reset per compilation unit, so the parser stops when a code is `0` or `<=` the previous code rather than relying on a terminator.

**Per-function fields (2026-07 extractor fix — regenerate old dumps).** `funcs()` emits `low_pc` (`DW_AT_low_pc`, or `None`), `linkage` (`DW_AT_MIPS_linkage_name`, the mangled C++ name — often present when `name` is the demangled or source name), and `cu` (the containing compilation unit's `.debug_info` offset, which is the grouping key for bias recovery below). `variables()` likewise carries `linkage` and `cu` alongside the `DW_OP_addr`-derived `addr`, and `json` mode includes the `vars` list. **Any `dwarf.json` produced before 2026-07-10 silently lacks all of these** — the extractor dropped them on the floor, which mislabeled whole binaries as "address-less DWARF, honest floor" for the RE-corpus naming campaigns. If a cached dump has no `low_pc` keys, re-parse the binary rather than trusting it.

### Per-CU address bias recovery (`dwarf_bias`)

**What it's for.** On SGI MIPS_DWARF2 shared libraries, `DW_AT_low_pc` values are frequently **un-relocated**: each CU's addresses are biased by some per-CU (sometimes per-*section*) constant relative to where the code actually landed in the linked binary. Matching DIEs to binary addresses with a naive zero bias then mis-names *every* function in a way that still passes structural gates — same count, same order, wrong names. `dwarf_bias` recovers the bias per CU and lands DIE names on real addresses, which is what turned the corpus's "unusable internal DWARF" into ~1,000+ recovered static-function names (campaign 4).

```python
from pyirix.debug.dwarf_bias import recover, classify_cu

# func_exports: {exported_name: binary_addr}  (from symbols.json / readelf dynsym)
# target_addrs: set of addresses you want names for (e.g. residue FUN_ addresses)
hits, cu_bias, stats = recover(binpath, func_exports, target_addrs)
# hits: [{name, die_low_pc, real_addr, cu, bias, ...}] — DIE names landed on real addresses
# cu_bias: {cu_offset: [candidate biases]};  classify_cu(cu_bias[cu]) → regime
```

**How it works.** For each CU it computes candidate biases as `dynsym_addr − DIE_low_pc` over **anchor** DIEs — functions whose (linkage-preferred) name is globally unique among the binary's exports, so the pairing is unambiguous. A CU whose anchors agree on one bias gets that bias applied to all its DIEs; the un-anchored DIEs then "land" on binary addresses.

**The three regimes (`classify_cu`), and how much to trust each:**
- **zero-bias** — anchors agree on bias 0; DIE addresses are identity-correct. Landings are trustworthy as-is (data symbols independently verifying bias 0 is the usual confirmation).
- **biased** — anchors agree on one nonzero bias. Same trust level as zero-bias once the bias is applied.
- **multi-section** — anchors disagree (the CU's text was split across sections at link time). Use the **dominant** bias (the one most anchors vote for) and treat every landing as a *candidate requiring a semantic spot-check* (does the body/wiring match the name?) before shipping. Do **not** pool multiple candidate biases per DIE — that manufactures collisions.
- **no-anchor** — a CU with no globally-unique exported function cannot be biased; its DIEs stay unusable. Common in comdat-heavy C++.

**Quirks worth knowing.**
- **Name collapse is the real yield limiter, not recovery.** Comdat template instantiation puts one DWARF name on N addresses; libil recovers 2,914 DIE hits that collapse to ~0 unique-nameable names. Always dedupe by name and discard non-unique landings before counting a "yield".
- Anchoring prefers `DW_AT_MIPS_linkage_name` over `name` — the mangled form is what actually matches dynsym on C++ libraries.
- The bias is per-**CU**, keyed on the `cu` field the `dwarf` parser stamps on each DIE; mixing DIEs across CUs under one bias is invalid.
- Data symbols (from `variables()`) are relocated normally (bias 0) even when function DIEs are biased — useful as an independent sanity check, useless as function anchors.
- Downstream consumers: `progress_notes/binary_re/pipeline/resweep_flag.py` ranks corpus trees by net-new nameable functions on top of `recover()`. Tests: `sgi-irix-re/tests/test_dwarf_bias.py` (libil fixture: 218/218 anchors zero-bias, 3,318 pool functions land by identity).

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
