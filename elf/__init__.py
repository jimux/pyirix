"""MIPS ELF analysis for IRIX binaries.

`deps` deconstructs an IRIX executable into the facts that decide whether it can
run under emulation: ABI/ISA, the shared libraries it needs (DT_NEEDED), the APIs
it imports, the libraries it dlopen()s, the /dev and /hw device nodes it touches,
the data assets it references, and — derived from all of those — a set of
*capability tags* (IRIS_GL, OPENGL_GLX, PERFORMER, AUDIO_HAL2, VINO, COSMO, ...).
"""
from pyirix.elf.deps import (
    ElfReport,
    Capability,
    analyze,
    classify_capabilities,
    CAPABILITY_RULES,
)

__all__ = [
    "ElfReport",
    "Capability",
    "analyze",
    "classify_capabilities",
    "CAPABILITY_RULES",
]
