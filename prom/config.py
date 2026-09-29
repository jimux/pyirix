# SGI PROM analysis - Configuration (PROM-general)
"""
Platform definitions (IP4-IP32) with sizes, interleave info.
Memory map constants and KSEG address mappings.

This is the PROM-general configuration owned by pyirix.prom and re-exported
by sgi_mcp.config. Ghidra/MCP-specific constants (GHIDRA_*) live in
sgi_mcp.config, not here.
"""

from dataclasses import dataclass
from typing import Optional, Tuple
from pathlib import Path


# PROM library root. The PROM images live under <workspace>/PROM_library, where
# the workspace root is the marker dir (.qemu-sgi-workspace) — NOT necessarily
# parents[2]. The code lives in a focused sub-repo (sgi-irix-re), so parents[2]
# is the REPO root and PROM_library is NOT under it (a real bug: relative PROM
# names resolved to nothing). Resolve the workspace root the way the rest of the
# tooling does; parents[2] is only a last resort.
def _prom_workspace_root() -> Path:
    try:
        import sgi_workspace
        return Path(sgi_workspace.workspace_root())
    except Exception:
        p = Path(__file__).resolve()
        for anc in [p] + list(p.parents):
            if (anc / ".qemu-sgi-workspace").exists():
                return anc
    return Path(__file__).resolve().parents[2]


PROM_DIR = _prom_workspace_root()
PROM_LIBRARY_DIR = PROM_DIR / "PROM_library"


# Memory map constants (KSEG1 addresses - uncached)
PROM_BASE = 0xbfc00000
MC_BASE = 0xbfa00000  # Memory Controller
HPC3_BASE = 0xbfb80000  # HPC3 (IP22/IP24)
HPC1_BASE = 0x1fb80000  # HPC1 (IP12/IP20)
IOC2_IP22 = 0xbfbd9000  # IOC2 for Indigo2
IOC2_IP24 = 0xbfbd9880  # IOC2 for Indy
GIO_GFX = 0xbf000000  # GIO64 Graphics slot
GIO_EXP0 = 0xbf400000  # GIO64 Expansion slot 0
GIO_EXP1 = 0xbf600000  # GIO64 Expansion slot 1

# Newport REX3 base addresses
REX3_BASE = 0xbf0f0000  # REX3 register base


# PROM header offsets
ENTRY_POINT_OFFSET = 0x18
PRINTF_VECTOR_OFFSET = 0x80
EXCEPTION_BEV_OFFSET = 0x180  # Exception vector in BEV mode (offset from PROM base)
EXCEPTION_NORMAL_OFFSET = 0x200  # TLB miss in normal mode


# KSEG address mappings
def kseg0_to_phys(addr: int) -> int:
    """Convert KSEG0 (cached) address to physical."""
    if 0x80000000 <= addr < 0xa0000000:
        return addr - 0x80000000
    return addr


def kseg1_to_phys(addr: int) -> int:
    """Convert KSEG1 (uncached) address to physical."""
    if 0xa0000000 <= addr < 0xc0000000:
        return addr - 0xa0000000
    return addr


def phys_to_kseg0(addr: int) -> int:
    """Convert physical address to KSEG0 (cached)."""
    if addr < 0x20000000:
        return addr + 0x80000000
    return addr


def phys_to_kseg1(addr: int) -> int:
    """Convert physical address to KSEG1 (uncached)."""
    if addr < 0x20000000:
        return addr + 0xa0000000
    return addr


def prom_offset_to_addr(offset: int, code_offset: int = 0,
                        code_base: int = PROM_BASE) -> int:
    """Convert a PROM FILE offset to its address.

    Plain PROM: ``code_offset == 0`` and ``code_base == PROM_BASE``, so this is
    the classic ``PROM_BASE + offset``. SN0/SN1 container: the MIPS image starts
    at ``code_offset`` and is based at ``code_base`` (both from the container
    header, i.e. ``PromCodeImage.code_offset``/``.code_base``), so a raw file
    offset must be rebased: ``code_base + (offset - code_offset)``.

    Carrying the classic form across a container lands every address off by
    ``code_offset`` — 0x1000 for ``ip35prom.img`` (code offset 0x1000 at header
    field 0x98). Callers that have a ``PromCodeImage`` (from
    ``load_prom_code``/``extract_prom_code``) MUST pass its ``code_offset`` and
    ``code_base`` rather than assume zero.
    """
    return code_base + (offset - code_offset)


def addr_to_prom_offset(addr: int, code_offset: int = 0,
                        code_base: Optional[int] = None,
                        code_size: int = 0) -> Optional[int]:
    """Convert a PROM address to its FILE offset (container-aware).

    ``code_offset``/``code_base``/``code_size`` come from the container header
    (``PromCodeImage``). When ``code_base`` is given, the address is mapped inside
    that code segment first; otherwise — and for a plain PROM — the classic
    KSEG1/KSEG0 rule is used.

    Address-form note: ``PromCodeImage.code_base`` is the **KSEG1** (0xbfc00000)
    form (``prom_code_base`` = phys + 0xa0000000). The same bytes are reachable at
    the K2 / "compat" form ``0xC0000000_xxxxxxxx`` (low 32 bits = phys + 0x1fc00000),
    which differs from ``code_base`` by 0xA0000000. Both forms are accepted here.
    """
    if code_base is not None and code_size:
        lo_base = code_base
        hi_base = code_base + code_size
        for cand in (addr, addr & 0xFFFFFFFF):
            if lo_base <= cand < hi_base:
                return code_offset + (cand - code_base)
        # K2/compat form: its 32-bit base is code_base - 0xA0000000
        k2_base = lo_base - 0xA0000000
        for cand in (addr, addr & 0xFFFFFFFF):
            if k2_base <= cand < k2_base + code_size:
                return code_offset + (cand - k2_base)
    # Classic KSEG1
    if 0xbfc00000 <= addr < 0xc0000000:
        return addr - 0xbfc00000
    # Classic KSEG0
    if 0x9fc00000 <= addr < 0xa0000000:
        return addr - 0x9fc00000
    return None


@dataclass
class PlatformInfo:
    """Information about an SGI platform."""
    name: str
    ip_number: str
    typical_sizes: Tuple[int, ...]  # Expected PROM sizes in bytes
    cpu_arch: str  # "mips1", "mips2", "mips3", "mips4", "mips64"
    endian: str  # "big", "little"
    interleave: int  # Byte interleave for multi-chip PROMs
    has_mc: bool  # Has Memory Controller
    has_hpc: int  # HPC version (0=none, 1=HPC1, 3=HPC3)
    has_ioc: int  # IOC version (0=none, 2=IOC2)
    description: str
    # IP30 Octane specific
    has_heart: bool = False  # Has Heart ASIC (IP30)
    has_xbow: bool = False   # Has Xbow crossbar (IP30)
    # IP32 O2 specific
    has_crime: bool = False  # Has CRIME ASIC (IP32)


# Platform definitions
PLATFORMS = {
    "ip4": PlatformInfo(
        name="Professional IRIS 4D/50",
        ip_number="IP4",
        typical_sizes=(262144,),  # 256KB
        cpu_arch="mips1",
        endian="big",
        interleave=1,
        has_mc=False,
        has_hpc=0,
        has_ioc=0,
        description="Early MIPS workstation"
    ),
    "ip6": PlatformInfo(
        name="4D/20",
        ip_number="IP6",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips1",
        endian="big",
        interleave=1,
        has_mc=False,
        has_hpc=0,
        has_ioc=0,
        description="Personal IRIS workstation"
    ),
    "ip12": PlatformInfo(
        name="Indigo R3000 / 4D/35",
        ip_number="IP12",
        typical_sizes=(262144, 524288),  # 256KB, 512KB
        cpu_arch="mips1",
        endian="big",
        interleave=1,
        has_mc=False,
        has_hpc=1,
        has_ioc=0,
        description="Indigo with R3000"
    ),
    "ip15": PlatformInfo(
        name="4D/4x0",
        ip_number="IP15",
        typical_sizes=(131072,),  # 128KB
        cpu_arch="mips2",
        endian="big",
        interleave=1,
        has_mc=False,
        has_hpc=0,
        has_ioc=0,
        description="Power Series"
    ),
    "ip17": PlatformInfo(
        name="Crimson",
        ip_number="IP17",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips3",
        endian="big",
        interleave=1,
        has_mc=False,
        has_hpc=0,
        has_ioc=0,
        description="Crimson deskside"
    ),
    "ip20": PlatformInfo(
        name="Indigo R4000",
        ip_number="IP20",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips3",
        endian="big",
        interleave=1,
        has_mc=True,
        has_hpc=1,
        has_ioc=0,
        description="Indigo with R4000"
    ),
    "ip22": PlatformInfo(
        name="Indigo2",
        ip_number="IP22",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips3",
        endian="big",
        interleave=1,
        has_mc=True,
        has_hpc=3,
        has_ioc=2,
        description="Indigo2 (Full House)"
    ),
    "ip24": PlatformInfo(
        name="Indy",
        ip_number="IP24",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips3",
        endian="big",
        interleave=1,
        has_mc=True,
        has_hpc=3,
        has_ioc=2,
        description="Indy (Guinness)"
    ),
    "ip26": PlatformInfo(
        name="Indigo2 Power",
        ip_number="IP26",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips64",  # R8000 uses 64-bit instructions
        endian="big",
        interleave=1,
        has_mc=True,
        has_hpc=3,
        has_ioc=2,
        description="Indigo2 with R8000 (MIPS64)"
    ),
    "ip27": PlatformInfo(
        name="Origin 200/2000 (Onyx2)",
        ip_number="IP27",
        # SN0 container file sizes measured in the corpus (raw flash differs);
        # ip27prom.img and its possible duplicate.
        typical_sizes=(912760, 895760),
        cpu_arch="mips64",  # R10000 (MIPS IV)
        endian="big",
        interleave=1,
        has_mc=False,   # Hub ASIC integrates memory; no IP22-class MC
        has_hpc=0,      # Hub/IOC3/Bridge, not HPC1/HPC3
        has_ioc=0,      # IOC3, not IOC2
        description="Origin 200/2000 Onyx2 (Hub/Xbow/Bridge, SN0 container)"
    ),
    "ip28": PlatformInfo(
        name="Indigo2 Impact",
        ip_number="IP28",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips64",  # R10000 uses 64-bit instructions
        endian="big",
        interleave=1,
        has_mc=True,
        has_hpc=3,
        has_ioc=2,
        description="Indigo2 with R10000 (MIPS64)"
    ),
    "ip30": PlatformInfo(
        name="Octane",
        ip_number="IP30",
        typical_sizes=(1048576,),  # 1MB
        cpu_arch="mips64",  # R10000/R12000 uses 64-bit instructions
        endian="big",
        interleave=1,
        has_mc=False,  # Uses HEART instead
        has_hpc=0,
        has_ioc=0,
        description="Octane workstation (Heart/Xbow architecture)",
        has_heart=True,
        has_xbow=True,
    ),
    "ip32": PlatformInfo(
        name="O2",
        ip_number="IP32",
        typical_sizes=(524288,),  # 512KB
        cpu_arch="mips64",  # R5000/R10000/R12000 uses 64-bit instructions
        endian="big",
        interleave=1,
        has_mc=False,  # Uses CRIME instead
        has_hpc=0,
        has_ioc=0,
        description="O2 workstation (CRIME architecture)",
        has_crime=True,
    ),
    "ip35": PlatformInfo(
        name="Origin 3000/Onyx 3000 (Tezro)",
        ip_number="IP35",
        # SN1 container file size measured in the corpus (raw flash differs).
        typical_sizes=(1477560,),
        cpu_arch="mips64",  # R12000/R14000 (MIPS IV)
        endian="big",
        interleave=1,
        has_mc=False,   # Bedrock/Hub integrates memory; no IP22-class MC
        has_hpc=0,      # Hub/IOC3/Bridge, not HPC1/HPC3
        has_ioc=0,      # IOC3, not IOC2
        description="Origin 3000/Onyx 3000 Tezro (Bedrock, SN1 container)"
    ),
}


def detect_platform(filename: str) -> Optional[str]:
    """
    Detect platform from filename.

    Examples:
        "Indy_ip24prom.070-9101-007.bin" -> "ip24"
        "4D20_ip6prom.BE.bin" -> "ip6"
    """
    filename_lower = filename.lower()

    # Try to find ipXX pattern
    import re
    match = re.search(r'ip(\d+)', filename_lower)
    if match:
        ip_num = f"ip{match.group(1)}"
        if ip_num in PLATFORMS:
            return ip_num

    # Try system name matching
    if 'indy' in filename_lower:
        return 'ip24'
    elif 'indigo_2' in filename_lower or 'indigo2' in filename_lower:
        # Could be IP22, IP26, or IP28
        if 'ip26' in filename_lower:
            return 'ip26'
        elif 'ip28' in filename_lower:
            return 'ip28'
        return 'ip22'
    elif 'indigo' in filename_lower:
        if 'ip20' in filename_lower:
            return 'ip20'
        return 'ip12'
    elif 'o2' in filename_lower:
        return 'ip32'
    elif 'octane' in filename_lower:
        return 'ip30'
    elif 'crimson' in filename_lower:
        return 'ip17'
    elif '4d35' in filename_lower:
        return 'ip12'
    elif '4d20' in filename_lower:
        return 'ip6'
    elif '4d420' in filename_lower or '4d4x0' in filename_lower:
        return 'ip15'
    elif 'professional' in filename_lower and 'iris' in filename_lower:
        return 'ip4'
    # SN machines by system name (the ipNN token is absent in these names):
    # Tezro / Onyx 3000 / Origin 3000 are IP35 (SN1); Onyx2 / Origin 200/2000
    # are IP27 (SN0). 'origin200' matches both Origin 200 and Origin 2000.
    elif 'tezro' in filename_lower or 'onyx3000' in filename_lower \
            or 'origin3000' in filename_lower:
        return 'ip35'
    elif 'onyx2' in filename_lower or 'origin200' in filename_lower:
        return 'ip27'

    return None


def get_cpu_mode(platform_id: str) -> str:
    """Get Capstone CPU mode for a platform."""
    if platform_id not in PLATFORMS:
        return "mips3"

    platform = PLATFORMS[platform_id]
    return platform.cpu_arch


def is_mips64_platform(platform_id: str) -> bool:
    """Check if a platform uses MIPS64 instructions."""
    if platform_id not in PLATFORMS:
        return False
    return PLATFORMS[platform_id].cpu_arch == "mips64"


def is_heart_xbow_platform(platform_id: str) -> bool:
    """Check if a platform uses Heart/Xbow architecture (IP30)."""
    if platform_id not in PLATFORMS:
        return False
    platform = PLATFORMS[platform_id]
    return getattr(platform, 'has_heart', False) and getattr(platform, 'has_xbow', False)
