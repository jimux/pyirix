"""pyirix.kernel — static analysis of SGI/IRIX MIPS ELF binaries.

Tools for inspecting kernel and userland MIPS binaries from disk images:
disassembly, symbol lookup, string references, syscall/ioctl inventory,
direct-call graph, data references, and DWARF type recovery.

All modules operate offline on extracted ELF files — no QEMU involvement.
Output is JSON (machine-readable) or human-readable disassembly listings.
"""
