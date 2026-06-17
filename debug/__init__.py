"""pyirix.debug — debugging and reverse engineering tools for SGI/IRIX.

Two halves under one roof:

  STATIC (no QEMU, just files): analyse extracted ELF binaries — disassembly,
  symbol lookup, string references, syscall/ioctl inventory, direct-call
  graph, data references, MIPS asm/disasm helpers, and DWARF type recovery.
    • dwarf.py        — minimal from-scratch DWARF2 parser
    • disasm.py       — disassemble a kernel function by name
    • mips_disasm.py  — capstone MIPS64/BE wrapper w/ hw annotations
    • mipsasm.py      — assemble MIPS asm → BE words (PROM trampolines)
    • strings.py      — resolve absolute lui+addiu/ori string refs
    • syscalls.py     — inventory ioctl command constants
    • xref.py         — find callers via `jal <target>` scan
    • callgraph.py    — whole-binary direct-call graph
    • dataref.py      — find data-word + lui+addiu data references
    • syms.py         — generate canonical kernel-symbol JSON from ELF
    • modules.py      — partition DWARF-bearing IRIX ELFs into source modules

  LIVE (talks to a running QEMU guest):
    • guest_gdb.py    — drive gdb-multiarch against the guest MIPS64 kernel
                        (breakpoints, KSEG0 memory peek, hardware watch,
                        replay-mode reverse-stepi). Requires a QEMU gdbstub.

The static tools accept an extracted ELF + optional symbol JSON; output is
JSON or human-readable. The live tool needs a QEMU process exposing -gdb.
"""
