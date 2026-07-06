"""Deconstruct an IRIX MIPS ELF into dependency + capability facts.

Uses pyelftools (already a pyirix dependency, see pyirix/debug/modules.py) to read
the dynamic section, dynamic symbol table, and program/section headers, plus a
LUI+ADDIU-aware string scan of loadable sections for dlopen targets, device-node
paths, and data-asset references.

Primary entry point:

    from pyirix import elf
    rep = elf.analyze("/path/to/demo")
    rep.capabilities   # [Capability(tag='IRIS_GL', reason=..., evidence=[...]), ...]
    rep.as_dict()      # JSON-serializable
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection
    _HAVE_PYELF = True
except Exception:  # pragma: no cover - pyelftools is expected present
    _HAVE_PYELF = False

# --- MIPS e_flags decoding ------------------------------------------------
EF_MIPS_ABI2 = 0x00000020          # set => N32
EF_MIPS_PIC = 0x00000002
EF_MIPS_CPIC = 0x00000004
_EF_MIPS_ABI_MASK = 0x0000F000
_EF_MIPS_ABI = {
    0x00001000: "o32",
    0x00002000: "o64",
    0x00003000: "eabi32",
    0x00004000: "eabi64",
}
_EF_MIPS_ARCH_MASK = 0xF0000000
_EF_MIPS_ARCH = {
    0x00000000: "mips1",
    0x10000000: "mips2",
    0x20000000: "mips3",
    0x30000000: "mips4",
    0x40000000: "mips5",
    0x50000000: "mips32",
    0x60000000: "mips64",
    0x70000000: "mips32r2",
    0x80000000: "mips64r2",
}

# --- string-scan patterns -------------------------------------------------
# Embedded strings that signal a runtime resource or hardware dependency.
_RE_DLOPEN_LIB = re.compile(rb"\b(lib[\w.+-]+\.so(?:\.\d+)*)")
_RE_DEVICE = re.compile(rb"(/dev/[\w./-]+|/hw/[\w./-]+)")
_RE_ASSET = re.compile(
    rb"([\w./+-]+\.(?:rgb|bw|sgi|inv|iv|sm|pdb|aiff|aifc|wav|mov|mpg|mpeg|"
    rb"obj|geo|tdr|nff|off|bin|tex|pfb|pfa|fnt|data|dat))",
)
_PRINTABLE = re.compile(rb"[\x20-\x7e]{3,}")


@dataclass
class Capability:
    tag: str
    reason: str
    evidence: list = field(default_factory=list)

    def as_dict(self):
        return {"tag": self.tag, "reason": self.reason, "evidence": self.evidence}


@dataclass
class ElfReport:
    path: str
    is_elf: bool = False
    elf_class: int = 0          # 32 or 64
    endian: str = ""            # 'big' / 'little'
    machine: str = ""           # 'EM_MIPS' or other
    abi: str = "unknown"        # o32 / n32 / n64 / ...
    isa: str = "unknown"        # mips1..mips4 ...
    pic: bool = False
    e_type: str = ""            # ET_EXEC / ET_DYN / ET_REL
    interp: str | None = None
    soname: str | None = None
    stripped: bool = True
    needed: list = field(default_factory=list)
    rpath: list = field(default_factory=list)
    runpath: list = field(default_factory=list)
    imported_syms: list = field(default_factory=list)
    dlopen_libs: list = field(default_factory=list)
    device_refs: list = field(default_factory=list)
    asset_refs: list = field(default_factory=list)
    capabilities: list = field(default_factory=list)
    error: str | None = None

    def cap_tags(self) -> list:
        return [c.tag for c in self.capabilities]

    def as_dict(self):
        d = dict(self.__dict__)
        d["capabilities"] = [c.as_dict() for c in self.capabilities]
        return d


def _decode_flags(e_flags: int, elf_class: int):
    abi2 = bool(e_flags & EF_MIPS_ABI2)
    abi_bits = e_flags & _EF_MIPS_ABI_MASK
    if abi2:
        abi = "n32"
    elif abi_bits in _EF_MIPS_ABI:
        abi = _EF_MIPS_ABI[abi_bits]
    elif elf_class == 64:
        abi = "n64"
    else:
        abi = "o32"
    isa = _EF_MIPS_ARCH.get(e_flags & _EF_MIPS_ARCH_MASK, "unknown")
    pic = bool(e_flags & (EF_MIPS_PIC | EF_MIPS_CPIC))
    return abi, isa, pic


def _read_raw_header(data: bytes):
    """Minimal ELF header read without pyelftools (fallback / pre-check)."""
    if len(data) < 24 or data[:4] != b"\x7fELF":
        return None
    elf_class = 32 if data[4] == 1 else 64
    endian = "big" if data[5] == 2 else "little"
    end = ">" if endian == "big" else "<"
    e_type = struct.unpack(end + "H", data[16:18])[0]
    e_machine = struct.unpack(end + "H", data[18:20])[0]
    if elf_class == 32:
        e_flags = struct.unpack(end + "I", data[36:40])[0]
    else:
        e_flags = struct.unpack(end + "I", data[48:52])[0]
    return elf_class, endian, e_type, e_machine, e_flags


_ETYPE = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}


def _string_scan(elf: "ELFFile", rep: ElfReport):
    """Scan loadable PROGBITS sections for dlopen libs, devices, assets."""
    libs, devs, assets = set(), set(), set()
    for sec in elf.iter_sections():
        # Real code/data (PROGBITS) carries dlopen/device/asset string literals.
        # Also include .dynstr: IRIX registers shared libs there beyond DT_NEEDED
        # (e.g. libX11.so.1), and it holds only lib/symbol names — no section names
        # or asset paths. We deliberately skip .shstrtab/.strtab, whose ELF section
        # names (".MIPS.events", ...) would otherwise pollute the asset scan.
        if sec["sh_type"] != "SHT_PROGBITS" and sec.name != ".dynstr":
            continue
        if sec["sh_size"] == 0 or sec["sh_size"] > 16 * 1024 * 1024:
            continue
        try:
            blob = sec.data()
        except Exception:
            continue
        for m in _RE_DLOPEN_LIB.finditer(blob):
            libs.add(m.group(1).decode("latin-1"))
        for m in _RE_DEVICE.finditer(blob):
            devs.add(m.group(1).decode("latin-1"))
        for m in _RE_ASSET.finditer(blob):
            a = m.group(1).decode("latin-1")
            if not a.startswith("lib") or not a.endswith(".so"):
                assets.add(a)
    # NEEDED libs already captured separately; dlopen_libs = extra .so refs.
    needed = set(rep.needed)
    rep.dlopen_libs = sorted(l for l in libs if l not in needed)
    rep.device_refs = sorted(devs)
    rep.asset_refs = sorted(assets)


def analyze(path: str) -> ElfReport:
    """Deconstruct one ELF file. Never raises on bad input; sets rep.error."""
    rep = ElfReport(path=path)
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError as e:
        rep.error = f"open failed: {e}"
        return rep

    raw = _read_raw_header(head)
    if raw is None:
        rep.error = "not an ELF"
        return rep
    rep.is_elf = True
    elf_class, endian, e_type, e_machine, e_flags = raw
    rep.elf_class = elf_class
    rep.endian = endian
    rep.e_type = _ETYPE.get(e_type, f"0x{e_type:x}")
    rep.machine = "EM_MIPS" if e_machine == 8 else f"machine_{e_machine}"
    if e_machine == 8:
        rep.abi, rep.isa, rep.pic = _decode_flags(e_flags, elf_class)

    if not _HAVE_PYELF:
        rep.error = "pyelftools unavailable; header-only result"
        return rep

    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            # interp
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_INTERP":
                    rep.interp = seg.get_interp_name()
                    break
            # dynamic: NEEDED / SONAME / RPATH / RUNPATH
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        t = tag.entry.d_tag
                        if t == "DT_NEEDED":
                            rep.needed.append(tag.needed)
                        elif t == "DT_SONAME":
                            rep.soname = tag.soname
                        elif t == "DT_RPATH":
                            rep.rpath.append(getattr(tag, "rpath", ""))
                        elif t == "DT_RUNPATH":
                            rep.runpath.append(getattr(tag, "runpath", ""))
                if isinstance(sec, SymbolTableSection) and sec.name == ".symtab":
                    rep.stripped = False
            # imported (undefined) dynamic symbols
            dynsym = elf.get_section_by_name(".dynsym")
            if isinstance(dynsym, SymbolTableSection):
                imp = set()
                for sym in dynsym.iter_symbols():
                    if not sym.name:
                        continue
                    if sym["st_shndx"] == "SHN_UNDEF" and sym["st_info"]["type"] in (
                        "STT_FUNC", "STT_OBJECT", "STT_NOTYPE",
                    ):
                        imp.add(sym.name)
                rep.imported_syms = sorted(imp)
            _string_scan(elf, rep)
    except Exception as e:  # keep partial header facts on any parse failure
        rep.error = f"pyelftools parse: {e}"

    rep.capabilities = classify_capabilities(rep)
    return rep


# --- capability classification -------------------------------------------
# Each rule: (tag, reason, lib_substrings, sym_substrings, device_substrings).
# A rule fires if ANY of its evidence lists matches; matched tokens are recorded.
CAPABILITY_RULES = [
    ("IRIS_GL", "links IRIS GL (libgl -> DGL render path)",
     ["libgl.so"], ["bgnpolygon", "winopen", "RGBcolor", "czclear", "gconfig"], []),
    ("OPENGL_GLX", "links OpenGL / GLX (libGL, hardware GL path)",
     ["libGL.so", "libGLU", "libGLw", "libGLcore"], ["glBegin", "glXCreateContext", "glClear", "gluPerspective"], []),
    ("PERFORMER", "IRIS Performer scene-graph (libpf*)",
     ["libpf", "libpfdu", "libpfutil", "libpfui", "libpfdb"], ["pfInit", "pfConfig", "pfNewChan"], []),
    ("OPEN_INVENTOR", "Open Inventor 3D toolkit (libInventor)",
     ["libInventor", "libInventorXt"], ["SoDB", "SoXt", "SoSeparator"], []),
    ("COSMO3D", "Cosmo3D / OpenGL Optimizer scene API",
     ["libcosmo", "libCosmo", "liboptimizer", "libcsdraw"], ["csContext", "opViewer"], []),
    ("AUDIO_HAL2", "audio library (AL / HAL2 PCM path)",
     ["libaudio.so"], ["ALopenport", "ALwritesamps", "alOpenPort", "alWriteFrames"], []),
    ("AUDIOFILE", "audio file I/O (libaudiofile)",
     ["libaudiofile"], ["afOpenFile", "afReadFrames"], []),
    ("MIDI", "MIDI I/O",
     ["libmd.so", "libmidi"], ["mdInit", "mdOpenInPort", "mdOpenOutPort"], ["/dev/midi", "/hw/midi"]),
    ("VIDEO_VL", "video library (VL — capture/output path)",
     ["libvl.so"], ["vlOpenVideo", "vlGetDevice", "vlBeginTransfer"], []),
    ("VINO", "VINO video capture device (IP22 video-in)",
     [], ["vlGetNode"], ["/dev/vino", "/hw/video", "/dev/video"]),
    ("DMEDIA", "digital media framework (libdmedia)",
     ["libdmedia"], ["dmGetParams", "dmICCreate"], []),
    ("MOVIE", "movie playback/authoring (libmovie)",
     ["libmovie", "libmoviefile"], ["mvOpenFile", "mvBindMediaData"], []),
    ("COMPRESSION_LIBCL", "compression library (libcl — Cosmo JPEG/MPEG)",
     ["libcl.so"], ["clOpenCompressor", "clCompress", "clDecompress"], []),
    ("GFX_DIRECT", "direct graphics device access (REX3 / gfx node)",
     [], [], ["/dev/gfx", "/dev/grafx", "/dev/cpu/gfx"]),
    ("X11", "X11 / Motif GUI",
     ["libX11", "libXt", "libXm", "libXmu", "libXext"], ["XOpenDisplay", "XtAppInitialize"], []),
]

# Tags that are merely "baseline GUI" — not a specialized-hardware gate.
_BASELINE_TAGS = {"X11"}


def classify_capabilities(rep: ElfReport) -> list:
    """Derive capability tags from a populated ElfReport."""
    # Library names are matched CASE-SENSITIVELY: on IRIX `libgl.so` (IRIS GL)
    # and `libGL.so` (OpenGL) are different libraries distinguished only by case.
    all_libs = list(rep.needed) + list(rep.dlopen_libs)
    syms = set(rep.imported_syms)
    devs = list(rep.device_refs)

    caps = []
    for tag, reason, lib_subs, sym_subs, dev_subs in CAPABILITY_RULES:
        evidence = []
        for sub in lib_subs:
            for lib in all_libs:
                if sub in lib:
                    evidence.append(f"lib:{lib}")
        for sub in sym_subs:
            for s in syms:
                if sub in s:
                    evidence.append(f"sym:{s}")
        for sub in dev_subs:
            for d in devs:
                if sub in d:
                    evidence.append(f"dev:{d}")
        if evidence:
            # de-dup + cap evidence list length for readability
            ev = sorted(set(evidence))[:8]
            caps.append(Capability(tag=tag, reason=reason, evidence=ev))
    return caps
