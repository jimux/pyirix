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


# PROM sample directory (project root, where the *.bin PROM images live).
# pyirix/prom/config.py -> parents[2] == project root.
PROM_DIR = Path(__file__).resolve().parents[2]


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


def prom_offset_to_addr(offset: int) -> int:
    """Convert PROM file offset to KSEG1 address."""
    return PROM_BASE + offset


def addr_to_prom_offset(addr: int) -> Optional[int]:
    """Convert KSEG1/KSEG0 PROM address to file offset."""
    # KSEG1 address
    if 0xbfc00000 <= addr < 0xc0000000:
        return addr - 0xbfc00000
    # KSEG0 address
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
