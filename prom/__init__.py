"""pyirix.prom — SGI PROM support: address math, platform definitions, and a
PROM file loader. Used by pyirix.debug.mips_disasm and re-exported by
sgi_mcp.config / sgi_mcp.hardware_defs / sgi_mcp.prom_loader.

Ghidra/MCP-specific configuration (the GHIDRA_* constants and
get_ghidra_language) lives in sgi_mcp.config, not here.
"""

from pyirix.prom.config import (
    PROM_DIR,
    PROM_BASE, MC_BASE, HPC3_BASE, HPC1_BASE, IOC2_IP22, IOC2_IP24,
    GIO_GFX, GIO_EXP0, GIO_EXP1, REX3_BASE,
    ENTRY_POINT_OFFSET, PRINTF_VECTOR_OFFSET,
    EXCEPTION_BEV_OFFSET, EXCEPTION_NORMAL_OFFSET,
    kseg0_to_phys, kseg1_to_phys, phys_to_kseg0, phys_to_kseg1,
    prom_offset_to_addr, addr_to_prom_offset,
    PlatformInfo, PLATFORMS, detect_platform, get_cpu_mode,
    is_mips64_platform, is_heart_xbow_platform,
)
from pyirix.prom.hardware_defs import (
    annotate_address, format_annotation, get_lui_annotation,
)
from pyirix.prom.prom_loader import (
    load_prom, get_prom_metadata, normalize_data, PromMetadata,
)
