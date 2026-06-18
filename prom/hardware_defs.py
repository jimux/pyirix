# SGI PROM Comparative Analysis - Hardware Register Definitions
"""
Register definitions ported from MAME and NetBSD sources.
Provides hardware annotations for memory-mapped I/O addresses.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple


@dataclass
class RegisterDef:
    """Definition of a hardware register."""
    name: str
    offset: int
    size: int  # in bytes (1, 2, 4, 8)
    access: str  # "R", "W", "RW"
    description: str


@dataclass
class DeviceDef:
    """Definition of a hardware device."""
    name: str
    base_address: int
    size: int
    registers: List[RegisterDef]
    description: str


# Memory Controller (MC) registers from mc.cpp
# Base: 0xbfa00000 (KSEG1) / 0x1fa00000 (physical)
MC_REGISTERS = [
    RegisterDef("CPU_CTRL0", 0x0000, 4, "RW", "CPU Control Register 0"),
    RegisterDef("CPU_CTRL1", 0x0008, 4, "RW", "CPU Control Register 1"),
    RegisterDef("WATCHDOG", 0x0010, 4, "RW", "Watchdog Timer"),
    RegisterDef("SYSID", 0x0018, 4, "R", "System ID (rev C=0x03, EISA bit 4)"),
    RegisterDef("RPSS_DIV", 0x0028, 4, "RW", "RPSS Divider"),
    RegisterDef("EEPROM", 0x0030, 4, "RW", "R4000 EEPROM Control (CS:1, CLK:2, DO:3, DI:4)"),
    RegisterDef("REFCNT_PRELOAD", 0x0040, 4, "RW", "Refresh Count Preload"),
    RegisterDef("REFCNT", 0x0048, 4, "R", "Refresh Count"),
    RegisterDef("GIO64_ARB", 0x0080, 4, "RW", "GIO64 Arbitration Parameters"),
    RegisterDef("CPU_TIME", 0x0088, 4, "RW", "Arbiter CPU Time"),
    RegisterDef("BURST_TIME", 0x0098, 4, "RW", "Arbiter Long Burst Time"),
    RegisterDef("MEMCFG0", 0x00c0, 4, "RW", "Memory Configuration 0 (Banks A/B)"),
    RegisterDef("MEMCFG1", 0x00c8, 4, "RW", "Memory Configuration 1 (Banks C/D)"),
    RegisterDef("CPU_MEMACC", 0x00d0, 4, "RW", "CPU Memory Access Config"),
    RegisterDef("GIO_MEMACC", 0x00d8, 4, "RW", "GIO Memory Access Config"),
    RegisterDef("CPU_ERR_ADDR", 0x00e0, 4, "R", "CPU Error Address"),
    RegisterDef("CPU_ERR_STAT", 0x00e8, 4, "RW", "CPU Error Status (write clears)"),
    RegisterDef("GIO_ERR_ADDR", 0x00f0, 4, "R", "GIO Error Address"),
    RegisterDef("GIO_ERR_STAT", 0x00f8, 4, "RW", "GIO Error Status (write clears)"),
    RegisterDef("SYS_SEMAPHORE", 0x0100, 4, "RW", "System Semaphore"),
    RegisterDef("GIO_LOCK", 0x0108, 4, "RW", "GIO Lock"),
    RegisterDef("EISA_LOCK", 0x0110, 4, "RW", "EISA Lock"),
    RegisterDef("GIO64_XLATE_MASK", 0x0150, 4, "RW", "GIO64 Translation Address Mask"),
    RegisterDef("GIO64_XLATE_SUBST", 0x0158, 4, "RW", "GIO64 Translation Substitution Bits"),
    RegisterDef("DMA_INT_CAUSE", 0x0160, 4, "RW", "DMA Interrupt Cause"),
    RegisterDef("DMA_CONTROL", 0x0168, 4, "RW", "DMA Control"),
    RegisterDef("DMA_TLB0_HI", 0x0180, 4, "RW", "DMA TLB Entry 0 High"),
    RegisterDef("DMA_TLB0_LO", 0x0188, 4, "RW", "DMA TLB Entry 0 Low"),
    RegisterDef("DMA_TLB1_HI", 0x0190, 4, "RW", "DMA TLB Entry 1 High"),
    RegisterDef("DMA_TLB1_LO", 0x0198, 4, "RW", "DMA TLB Entry 1 Low"),
    RegisterDef("DMA_TLB2_HI", 0x01a0, 4, "RW", "DMA TLB Entry 2 High"),
    RegisterDef("DMA_TLB2_LO", 0x01a8, 4, "RW", "DMA TLB Entry 2 Low"),
    RegisterDef("DMA_TLB3_HI", 0x01b0, 4, "RW", "DMA TLB Entry 3 High"),
    RegisterDef("DMA_TLB3_LO", 0x01b8, 4, "RW", "DMA TLB Entry 3 Low"),
    RegisterDef("RPSS_COUNTER", 0x1000, 4, "R", "RPSS Counter (time base)"),
    RegisterDef("DMA_MEM_ADDR", 0x2000, 4, "RW", "DMA Memory Address"),
    RegisterDef("DMA_SIZE", 0x2010, 4, "RW", "DMA Line Count and Width"),
    RegisterDef("DMA_STRIDE", 0x2018, 4, "RW", "DMA Line Zoom and Stride"),
    RegisterDef("DMA_GIO_ADDR", 0x2020, 4, "RW", "DMA GIO64 Address"),
    RegisterDef("DMA_GIO_ADDR_START", 0x2028, 4, "RW", "DMA GIO64 Address + Start"),
    RegisterDef("DMA_MODE", 0x2030, 4, "RW", "DMA Mode"),
    RegisterDef("DMA_COUNT", 0x2038, 4, "RW", "DMA Zoom/Byte Count"),
    RegisterDef("DMA_START", 0x2040, 4, "W", "DMA Start"),
    RegisterDef("DMA_RUN", 0x2048, 4, "R", "DMA Run Status"),
]

# HPC3 registers from hpc3.cpp
# Base: 0xbfb80000 (KSEG1) / 0x1fb80000 (physical)
HPC3_REGISTERS = [
    # PBUS DMA channels 0-7 at 0x0000-0x10000, each 0x2000 apart
    RegisterDef("PBUS_DMA0_BP", 0x0000, 4, "R", "PBUS DMA Ch0 Buffer Pointer"),
    RegisterDef("PBUS_DMA0_DP", 0x0004, 4, "RW", "PBUS DMA Ch0 Descriptor Pointer"),
    RegisterDef("PBUS_DMA0_CTRL", 0x1000, 4, "RW", "PBUS DMA Ch0 Control"),

    # SCSI DMA at 0x10000
    RegisterDef("SCSI0_CBP", 0x10000, 4, "R", "SCSI0 Current Buffer Pointer"),
    RegisterDef("SCSI0_NBDP", 0x10004, 4, "RW", "SCSI0 Next Buffer Desc Pointer"),
    RegisterDef("SCSI0_BC", 0x11000, 4, "RW", "SCSI0 Buffer Count"),
    RegisterDef("SCSI0_CTRL", 0x11004, 4, "RW", "SCSI0 DMA Control"),
    RegisterDef("SCSI0_GIO_FIFO", 0x11008, 4, "R", "SCSI0 GIO FIFO Pointer"),
    RegisterDef("SCSI0_DEV_FIFO", 0x1100c, 4, "R", "SCSI0 Device FIFO Pointer"),
    RegisterDef("SCSI0_DMACFG", 0x11010, 4, "RW", "SCSI0 DMA Config"),
    RegisterDef("SCSI0_PIOCFG", 0x11014, 4, "RW", "SCSI0 PIO Config"),

    RegisterDef("SCSI1_CBP", 0x12000, 4, "R", "SCSI1 Current Buffer Pointer"),
    RegisterDef("SCSI1_NBDP", 0x12004, 4, "RW", "SCSI1 Next Buffer Desc Pointer"),
    RegisterDef("SCSI1_BC", 0x13000, 4, "RW", "SCSI1 Buffer Count"),
    RegisterDef("SCSI1_CTRL", 0x13004, 4, "RW", "SCSI1 DMA Control"),
    RegisterDef("SCSI1_DMACFG", 0x13010, 4, "RW", "SCSI1 DMA Config"),
    RegisterDef("SCSI1_PIOCFG", 0x13014, 4, "RW", "SCSI1 PIO Config"),

    # Ethernet at 0x14000
    RegisterDef("ENET_RX_CBP", 0x14000, 4, "RW", "Ethernet Rx Current Buffer Pointer"),
    RegisterDef("ENET_RX_NBDP", 0x14004, 4, "RW", "Ethernet Rx Next Buffer Desc Pointer"),
    RegisterDef("ENET_RX_BC", 0x15000, 4, "R", "Ethernet Rx Buffer Count"),
    RegisterDef("ENET_RX_CTRL", 0x15004, 4, "RW", "Ethernet Rx DMA Control"),
    RegisterDef("ENET_MISC", 0x15014, 4, "RW", "Ethernet Reset/Misc"),
    RegisterDef("ENET_DMACFG", 0x15018, 4, "RW", "Ethernet DMA Config"),
    RegisterDef("ENET_PIOCFG", 0x1501c, 4, "RW", "Ethernet PIO Config"),
    RegisterDef("ENET_TX_CBP", 0x16000, 4, "R", "Ethernet Tx Current Buffer Pointer"),
    RegisterDef("ENET_TX_NBDP", 0x16004, 4, "RW", "Ethernet Tx Next Buffer Desc Pointer"),
    RegisterDef("ENET_TX_BC", 0x17000, 4, "R", "Ethernet Tx Buffer Count"),
    RegisterDef("ENET_TX_CTRL", 0x17004, 4, "RW", "Ethernet Tx DMA Control"),

    # FIFOs
    RegisterDef("PBUS_FIFO", 0x20000, 0x300, "RW", "PBUS FIFO"),
    RegisterDef("SCSI0_FIFO", 0x28000, 0x300, "RW", "SCSI0 FIFO"),
    RegisterDef("SCSI1_FIFO", 0x2a000, 0x300, "RW", "SCSI1 FIFO"),
    RegisterDef("ENET_RX_FIFO", 0x2c000, 0x100, "RW", "Ethernet Rx FIFO"),
    RegisterDef("ENET_TX_FIFO", 0x2e000, 0x140, "RW", "Ethernet Tx FIFO"),

    # Misc registers
    RegisterDef("INTSTAT", 0x30000, 4, "R", "Interrupt Status"),
    RegisterDef("MISC", 0x30004, 4, "RW", "Miscellaneous"),
    RegisterDef("EEPROM", 0x30008, 4, "RW", "Serial EEPROM Control"),

    # SCSI registers (WD33C93B)
    RegisterDef("SCSI0_REGS", 0x40000, 0x8000, "RW", "SCSI0 Controller (WD33C93B)"),
    RegisterDef("SCSI1_REGS", 0x48000, 0x8000, "RW", "SCSI1 Controller (WD33C93B)"),

    # Ethernet chip (SEEQ 80C03)
    RegisterDef("ENET_REGS", 0x54000, 0x500, "RW", "Ethernet Controller (SEEQ 80C03)"),

    # PIO
    RegisterDef("PIO_DATA", 0x58000, 0x4000, "RW", "PIO Data Channels"),
    RegisterDef("DMA_CONFIG", 0x5c000, 0x1000, "RW", "DMA Configuration"),
    RegisterDef("PIO_CONFIG", 0x5d000, 0x1000, "RW", "PIO Configuration"),

    # BBRAM
    RegisterDef("BBRAM", 0x60000, 0x20000, "RW", "Battery-Backed RAM"),
]

# IOC2 registers from ioc2.cpp (INT3 for Indy/Indigo2)
# IP22: 0xbfbd9000, IP24: 0xbfbd9880
IOC2_REGISTERS = [
    RegisterDef("PI1_DATA", 0x00, 1, "RW", "Parallel Port Data"),
    RegisterDef("PI1_STATUS", 0x01, 1, "R", "Parallel Port Status"),
    RegisterDef("PI1_CTRL", 0x02, 1, "RW", "Parallel Port Control"),
    RegisterDef("PI1_DMA_CTRL", 0x03, 1, "RW", "Parallel Port DMA Control"),
    RegisterDef("PI1_INT_STATUS", 0x04, 1, "RW", "Parallel Port Interrupt Status"),
    RegisterDef("PI1_INT_MASK", 0x05, 1, "RW", "Parallel Port Interrupt Mask"),
    RegisterDef("PI1_TIMER1", 0x06, 1, "RW", "Parallel Port Timer 1"),
    RegisterDef("PI1_TIMER2", 0x07, 1, "RW", "Parallel Port Timer 2"),
    RegisterDef("PI1_TIMER3", 0x08, 1, "RW", "Parallel Port Timer 3"),
    RegisterDef("PI1_TIMER4", 0x09, 1, "RW", "Parallel Port Timer 4"),
    RegisterDef("SCC_A_CMD", 0x0c, 1, "RW", "Serial Port A Command"),
    RegisterDef("SCC_A_DATA", 0x0d, 1, "RW", "Serial Port A Data"),
    RegisterDef("SCC_B_CMD", 0x0e, 1, "RW", "Serial Port B Command"),
    RegisterDef("SCC_B_DATA", 0x0f, 1, "RW", "Serial Port B Data"),
    RegisterDef("KBDC_DATA", 0x10, 1, "RW", "Keyboard Controller Data"),
    RegisterDef("KBDC_STATUS", 0x11, 1, "R", "Keyboard Controller Status"),
    RegisterDef("KBDC_CMD", 0x11, 1, "W", "Keyboard Controller Command"),
    RegisterDef("GC_SELECT", 0x12, 1, "RW", "General Control Select"),
    RegisterDef("GEN_CTRL", 0x13, 1, "RW", "General Control"),
    RegisterDef("FRONT_PANEL", 0x14, 1, "RW", "Front Panel (power/volume buttons)"),
    RegisterDef("SYSTEM_ID", 0x16, 1, "R", "System ID"),
    RegisterDef("READ_REG", 0x18, 1, "R", "Read Register"),
    RegisterDef("DMA_SEL", 0x1a, 1, "RW", "DMA Select"),
    RegisterDef("RESET_REG", 0x1c, 1, "RW", "Reset Register"),
    RegisterDef("WRITE_REG", 0x1e, 1, "RW", "Write Register"),
    # INT3 registers (Guinness layout at 0x20+)
    RegisterDef("INT3_LOCAL0_STATUS", 0x20, 1, "R", "INT3 Local0 Interrupt Status"),
    RegisterDef("INT3_LOCAL0_MASK", 0x21, 1, "RW", "INT3 Local0 Interrupt Mask"),
    RegisterDef("INT3_LOCAL1_STATUS", 0x22, 1, "R", "INT3 Local1 Interrupt Status"),
    RegisterDef("INT3_LOCAL1_MASK", 0x23, 1, "RW", "INT3 Local1 Interrupt Mask"),
    RegisterDef("INT3_MAP_STATUS", 0x24, 1, "R", "INT3 Mappable Interrupt Status"),
    RegisterDef("INT3_MAP_MASK0", 0x25, 1, "RW", "INT3 Mappable Interrupt Mask 0"),
    RegisterDef("INT3_MAP_MASK1", 0x26, 1, "RW", "INT3 Mappable Interrupt Mask 1"),
    RegisterDef("INT3_MAP_POLARITY", 0x27, 1, "RW", "INT3 Mappable Interrupt Polarity"),
    RegisterDef("INT3_TIMER_CLEAR", 0x28, 1, "W", "INT3 Timer Interrupt Clear"),
    RegisterDef("INT3_ERROR_STATUS", 0x29, 1, "R", "INT3 Error Status"),
    RegisterDef("PIT_COUNTER0", 0x2c, 1, "RW", "8254 PIT Counter 0"),
    RegisterDef("PIT_COUNTER1", 0x2d, 1, "RW", "8254 PIT Counter 1"),
    RegisterDef("PIT_COUNTER2", 0x2e, 1, "RW", "8254 PIT Counter 2"),
    RegisterDef("PIT_CTRL", 0x2f, 1, "W", "8254 PIT Control"),
]

# Newport REX3 registers from newport.cpp
# Base: 0xbf0f0000
REX3_REGISTERS = [
    RegisterDef("DRAWMODE1", 0x0000, 4, "RW", "Draw Mode Register 1"),
    RegisterDef("DRAWMODE0", 0x0004, 4, "RW", "Draw Mode Register 0"),
    RegisterDef("LSMODE", 0x0008, 4, "RW", "Line Stipple Mode"),
    RegisterDef("LSPATTERN", 0x000c, 4, "RW", "Line Stipple Pattern"),
    RegisterDef("LSPATSAVE", 0x0010, 4, "RW", "Line Stipple Pattern Save"),
    RegisterDef("ZPATTERN", 0x0014, 4, "RW", "Z Pattern"),
    RegisterDef("COLORBACK", 0x0018, 4, "RW", "Background Color"),
    RegisterDef("COLORVRAM", 0x001c, 4, "RW", "VRAM Foreground Color"),
    RegisterDef("ALPHAREF", 0x0020, 4, "RW", "Alpha Reference"),
    RegisterDef("SMASK0X", 0x0024, 4, "RW", "Screenmask 0 X"),
    RegisterDef("SMASK0Y", 0x0028, 4, "RW", "Screenmask 0 Y"),
    RegisterDef("SETUP", 0x002c, 4, "RW", "Setup"),
    RegisterDef("STEPZ", 0x0030, 4, "RW", "Z Step"),
    RegisterDef("XSTART", 0x0100, 4, "RW", "X Start"),
    RegisterDef("YSTART", 0x0104, 4, "RW", "Y Start"),
    RegisterDef("XEND", 0x0108, 4, "RW", "X End"),
    RegisterDef("YEND", 0x010c, 4, "RW", "Y End"),
    RegisterDef("XSAVE", 0x0110, 4, "RW", "X Save"),
    RegisterDef("XYSTART", 0x0114, 8, "RW", "XY Start (Packed)"),
    RegisterDef("XYEND", 0x0118, 8, "RW", "XY End (Packed)"),
    RegisterDef("XYMOVE", 0x011c, 4, "RW", "XY Move"),
    RegisterDef("COLORI", 0x0130, 4, "RW", "Color Index"),
    RegisterDef("COLORRED", 0x0134, 4, "RW", "Red Component"),
    RegisterDef("COLORALPHA", 0x0138, 4, "RW", "Alpha Component"),
    RegisterDef("COLORGREEN", 0x013c, 4, "RW", "Green Component"),
    RegisterDef("COLORBLUE", 0x0140, 4, "RW", "Blue Component"),
    RegisterDef("SLOPERED", 0x0144, 4, "RW", "Red Slope"),
    RegisterDef("SLOPEGREEN", 0x014c, 4, "RW", "Green Slope"),
    RegisterDef("SLOPEBLUE", 0x0150, 4, "RW", "Blue Slope"),
    RegisterDef("WRMASK", 0x0200, 4, "RW", "Write Mask"),
    RegisterDef("HOTEFLAG", 0x0204, 4, "R", "HOTEFLAG"),
    RegisterDef("XSTARTI_FRAC", 0x0300, 4, "RW", "X Start Integer/Frac"),
    RegisterDef("YSTARTI_FRAC", 0x0308, 4, "RW", "Y Start Integer/Frac"),
    RegisterDef("XENDI_FRAC", 0x0310, 4, "RW", "X End Integer/Frac"),
    RegisterDef("YENDI_FRAC", 0x0318, 4, "RW", "Y End Integer/Frac"),
    RegisterDef("STATUS", 0x0800, 4, "R", "Status Register"),
    RegisterDef("GIOFLAG", 0x0804, 4, "R", "GIO Flag"),
    RegisterDef("DCBMODE", 0x0c00, 4, "RW", "DCB Mode"),
    RegisterDef("DCBDATA0", 0x0c04, 4, "RW", "DCB Data 0"),
    RegisterDef("DCBDATA1", 0x0c08, 4, "RW", "DCB Data 1"),
]


# =============================================================================
# IP30 Octane Hardware Definitions (Heart/Xbow Architecture)
# =============================================================================

# Heart ASIC registers (Octane memory/interrupt controller)
# Base: 0x0ff00000 (physical) / varies by widget
HEART_REGISTERS = [
    # Widget registers
    RegisterDef("HEART_WID_ID", 0x00000, 8, "R", "Widget Identification"),
    RegisterDef("HEART_WID_STAT", 0x00008, 8, "RW", "Widget Status"),
    RegisterDef("HEART_WID_ERR_UPPER", 0x00010, 8, "RW", "Widget Error Address Upper"),
    RegisterDef("HEART_WID_ERR_LOWER", 0x00018, 8, "RW", "Widget Error Address Lower"),
    RegisterDef("HEART_WID_CONTROL", 0x00020, 8, "RW", "Widget Control"),
    RegisterDef("HEART_WID_REQ_TIMEOUT", 0x00030, 8, "RW", "Widget Request Timeout"),
    RegisterDef("HEART_WID_INTDEST_UPPER", 0x00038, 8, "RW", "Widget Interrupt Dest Upper"),
    RegisterDef("HEART_WID_INTDEST_LOWER", 0x00040, 8, "RW", "Widget Interrupt Dest Lower"),
    RegisterDef("HEART_WID_ERR_CMDWORD", 0x00048, 8, "R", "Widget Error Command Word"),
    RegisterDef("HEART_WID_LLP", 0x00050, 8, "RW", "Widget LLP Configuration"),
    RegisterDef("HEART_WID_TARG_FLUSH", 0x00058, 8, "W", "Widget Target Flush"),

    # Heart-specific configuration
    RegisterDef("HEART_MODE", 0x00000, 8, "RW", "Heart Mode Register"),
    RegisterDef("HEART_SDRAM_MODE", 0x00008, 8, "RW", "SDRAM Mode"),
    RegisterDef("HEART_MEM_REF", 0x00010, 8, "RW", "Memory Refresh"),
    RegisterDef("HEART_MEM_REQ_ARB", 0x00018, 8, "RW", "Memory Request Arbitration"),

    # Memory configuration
    RegisterDef("HEART_MEMCFG0", 0x00100, 8, "RW", "Memory Configuration 0"),
    RegisterDef("HEART_MEMCFG1", 0x00108, 8, "RW", "Memory Configuration 1"),
    RegisterDef("HEART_MEMCFG2", 0x00110, 8, "RW", "Memory Configuration 2"),
    RegisterDef("HEART_MEMCFG3", 0x00118, 8, "RW", "Memory Configuration 3"),

    # Status and error registers
    RegisterDef("HEART_STATUS", 0x00200, 8, "R", "Heart Status"),
    RegisterDef("HEART_BERR_ADDR", 0x00208, 8, "R", "Bus Error Address"),
    RegisterDef("HEART_BERR_MISC", 0x00210, 8, "R", "Bus Error Miscellaneous"),
    RegisterDef("HEART_AC_BANK_STS", 0x00218, 8, "R", "AC Bank Status"),

    # Interrupt registers
    RegisterDef("HEART_IMR0", 0x10000, 8, "RW", "Interrupt Mask Register 0"),
    RegisterDef("HEART_IMR1", 0x10008, 8, "RW", "Interrupt Mask Register 1"),
    RegisterDef("HEART_IMR2", 0x10010, 8, "RW", "Interrupt Mask Register 2"),
    RegisterDef("HEART_IMR3", 0x10018, 8, "RW", "Interrupt Mask Register 3"),
    RegisterDef("HEART_SET_ISR", 0x10020, 8, "W", "Set Interrupt Status"),
    RegisterDef("HEART_CLR_ISR", 0x10028, 8, "W", "Clear Interrupt Status"),
    RegisterDef("HEART_ISR", 0x10030, 8, "R", "Interrupt Status Register"),
    RegisterDef("HEART_IMSR", 0x10038, 8, "R", "Interrupt Mode Status Register"),
    RegisterDef("HEART_CAUSE", 0x10040, 8, "R", "Interrupt Cause"),

    # CPU access regions
    RegisterDef("HEART_PIU_ACCESS", 0x20000, 8, "RW", "PIU Access"),
]

# Xbow Crossbar registers (widget interconnect)
# Base: 0x10000000 + widget offset
XBOW_REGISTERS = [
    RegisterDef("XBOW_WID_ID", 0x00, 4, "R", "Crossbow Widget ID"),
    RegisterDef("XBOW_WID_STAT", 0x08, 4, "RW", "Crossbow Widget Status"),
    RegisterDef("XBOW_WID_ERR_UPPER", 0x10, 4, "RW", "Error Address Upper"),
    RegisterDef("XBOW_WID_ERR_LOWER", 0x18, 4, "RW", "Error Address Lower"),
    RegisterDef("XBOW_WID_CONTROL", 0x20, 4, "RW", "Widget Control"),
    RegisterDef("XBOW_WID_REQ_TIMEOUT", 0x28, 4, "RW", "Request Timeout"),
    RegisterDef("XBOW_WID_INTDEST", 0x30, 4, "RW", "Interrupt Destination"),
    RegisterDef("XBOW_WID_ERR_CMDWORD", 0x38, 4, "R", "Error Command Word"),
    RegisterDef("XBOW_WID_LLP", 0x40, 4, "RW", "LLP Configuration"),
    RegisterDef("XBOW_WID_TARG_FLUSH", 0x48, 4, "W", "Target Flush"),
    RegisterDef("XBOW_WID_ARB_RELOAD", 0x50, 4, "RW", "Arbitration Reload Interval"),
    RegisterDef("XBOW_WID_PERF_CTR_A", 0x58, 4, "RW", "Performance Counter A"),
    RegisterDef("XBOW_WID_PERF_CTR_B", 0x60, 4, "RW", "Performance Counter B"),
    RegisterDef("XBOW_WID_NIC", 0x68, 4, "RW", "Number In Can (NIC)"),

    # Link registers for ports 8-F (0x100 per link)
    RegisterDef("XBOW_LINK8_IBUF_FLUSH", 0x100, 4, "W", "Link 8 Input Buffer Flush"),
    RegisterDef("XBOW_LINK8_CTRL", 0x108, 4, "RW", "Link 8 Control"),
    RegisterDef("XBOW_LINK8_STATUS", 0x110, 4, "R", "Link 8 Status"),
    RegisterDef("XBOW_LINK8_ARB_UPPER", 0x118, 4, "RW", "Link 8 Arbitration Upper"),
    RegisterDef("XBOW_LINK8_ARB_LOWER", 0x120, 4, "RW", "Link 8 Arbitration Lower"),
    RegisterDef("XBOW_LINK8_STATUS_CLR", 0x128, 4, "W", "Link 8 Status Clear"),
    RegisterDef("XBOW_LINK8_RESET", 0x130, 4, "W", "Link 8 Reset"),
    RegisterDef("XBOW_LINK8_AUX_STATUS", 0x138, 4, "R", "Link 8 Auxiliary Status"),

    # Additional links follow same pattern at +0x40 each
    RegisterDef("XBOW_LINK9_CTRL", 0x148, 4, "RW", "Link 9 Control"),
    RegisterDef("XBOW_LINKA_CTRL", 0x188, 4, "RW", "Link A Control"),
    RegisterDef("XBOW_LINKB_CTRL", 0x1c8, 4, "RW", "Link B Control"),
    RegisterDef("XBOW_LINKC_CTRL", 0x208, 4, "RW", "Link C Control"),
    RegisterDef("XBOW_LINKD_CTRL", 0x248, 4, "RW", "Link D Control"),
    RegisterDef("XBOW_LINKE_CTRL", 0x288, 4, "RW", "Link E Control"),
    RegisterDef("XBOW_LINKF_CTRL", 0x2c8, 4, "RW", "Link F Control"),
]

# BRIDGE ASIC registers (PCI to XIO bridge, used on IP30)
BRIDGE_REGISTERS = [
    RegisterDef("BRIDGE_WID_ID", 0x00000, 4, "R", "Bridge Widget ID"),
    RegisterDef("BRIDGE_WID_STAT", 0x00004, 4, "RW", "Bridge Widget Status"),
    RegisterDef("BRIDGE_WID_ERR_UPPER", 0x00008, 4, "RW", "Error Address Upper"),
    RegisterDef("BRIDGE_WID_ERR_LOWER", 0x0000c, 4, "RW", "Error Address Lower"),
    RegisterDef("BRIDGE_WID_CONTROL", 0x00010, 4, "RW", "Widget Control"),
    RegisterDef("BRIDGE_WID_REQ_TIMEOUT", 0x00014, 4, "RW", "Request Timeout"),
    RegisterDef("BRIDGE_WID_RESP_UPPER", 0x0001c, 4, "RW", "Response Buffer Upper"),
    RegisterDef("BRIDGE_WID_RESP_LOWER", 0x00020, 4, "RW", "Response Buffer Lower"),
    RegisterDef("BRIDGE_WID_TST_PIN_CTRL", 0x00024, 4, "RW", "Test Pin Control"),
    RegisterDef("BRIDGE_DIR_MAP", 0x00080, 4, "RW", "Direct Map"),
    RegisterDef("BRIDGE_RAM_PERR", 0x00088, 4, "RW", "RAM Parity Error"),
    RegisterDef("BRIDGE_ARB", 0x0008c, 4, "RW", "Arbitration"),
    RegisterDef("BRIDGE_NIC", 0x00090, 4, "RW", "Number In Can"),
    RegisterDef("BRIDGE_BUS_TIMEOUT", 0x00094, 4, "RW", "Bus Timeout"),
    RegisterDef("BRIDGE_PCI_BUS_TIMEOUT", 0x00098, 4, "RW", "PCI Bus Timeout"),
    RegisterDef("BRIDGE_PCI_CFG", 0x0009c, 4, "RW", "PCI Configuration"),
    RegisterDef("BRIDGE_PCI_ERR_UPPER", 0x000a0, 4, "R", "PCI Error Upper"),
    RegisterDef("BRIDGE_PCI_ERR_LOWER", 0x000a4, 4, "R", "PCI Error Lower"),
    RegisterDef("BRIDGE_INT_STATUS", 0x00100, 4, "R", "Interrupt Status"),
    RegisterDef("BRIDGE_INT_ENABLE", 0x00104, 4, "RW", "Interrupt Enable"),
    RegisterDef("BRIDGE_INT_RST_STAT", 0x00108, 4, "RW", "Interrupt Reset Status"),
    RegisterDef("BRIDGE_INT_MODE", 0x0010c, 4, "RW", "Interrupt Mode"),
    RegisterDef("BRIDGE_INT_DEV", 0x00110, 4, "RW", "Interrupt Device"),
    RegisterDef("BRIDGE_INT_HOST_ERR", 0x00114, 4, "RW", "Interrupt Host Error"),
    RegisterDef("BRIDGE_INT_ADDR0", 0x00118, 8, "RW", "Interrupt Address 0"),
    # Device registers
    RegisterDef("BRIDGE_DEVICE0", 0x00200, 4, "RW", "Device 0 Control"),
    RegisterDef("BRIDGE_DEVICE1", 0x00208, 4, "RW", "Device 1 Control"),
    RegisterDef("BRIDGE_DEVICE2", 0x00210, 4, "RW", "Device 2 Control"),
    RegisterDef("BRIDGE_DEVICE3", 0x00218, 4, "RW", "Device 3 Control"),
    RegisterDef("BRIDGE_DEVICE4", 0x00220, 4, "RW", "Device 4 Control"),
    RegisterDef("BRIDGE_DEVICE5", 0x00228, 4, "RW", "Device 5 Control"),
    RegisterDef("BRIDGE_DEVICE6", 0x00230, 4, "RW", "Device 6 Control"),
    RegisterDef("BRIDGE_DEVICE7", 0x00238, 4, "RW", "Device 7 Control"),
    # Write request buffer
    RegisterDef("BRIDGE_WR_REQ_BUF0", 0x00240, 4, "RW", "Write Request Buffer 0"),
    # RRB (Read Request Buffer)
    RegisterDef("BRIDGE_EVEN_RESP", 0x00280, 4, "RW", "Even RRB Response"),
    RegisterDef("BRIDGE_ODD_RESP", 0x00284, 4, "RW", "Odd RRB Response"),
    RegisterDef("BRIDGE_RESP_STATUS", 0x00288, 4, "R", "RRB Response Status"),
    RegisterDef("BRIDGE_RESP_CLEAR", 0x0028c, 4, "W", "RRB Response Clear"),
    # PCI type 0/1 config
    RegisterDef("BRIDGE_PCI_TYPE0_CFG", 0x20000, 0x1000, "RW", "PCI Type 0 Config Space"),
    RegisterDef("BRIDGE_PCI_TYPE1_CFG", 0x28000, 0x1000, "RW", "PCI Type 1 Config Space"),
]


# Build device definitions
DEVICES = {
    "MC": DeviceDef(
        name="Memory Controller",
        base_address=0xbfa00000,
        size=0x20000,
        registers=MC_REGISTERS,
        description="SGI Memory Controller (IP20/IP22/IP24/IP26/IP28)"
    ),
    "HPC3": DeviceDef(
        name="HPC3",
        base_address=0xbfb80000,
        size=0x80000,
        registers=HPC3_REGISTERS,
        description="High-Performance Peripheral Controller 3 (IP22/IP24)"
    ),
    "IOC2_IP24": DeviceDef(
        name="IOC2 (Indy)",
        base_address=0xbfbd9880,
        size=0x40,
        registers=IOC2_REGISTERS,
        description="I/O Controller 2 - INT3 (Indy/Guinness)"
    ),
    "IOC2_IP22": DeviceDef(
        name="IOC2 (Indigo2)",
        base_address=0xbfbd9000,
        size=0x40,
        registers=IOC2_REGISTERS,
        description="I/O Controller 2 - INT3 (Indigo2/Full House)"
    ),
    "REX3": DeviceDef(
        name="Newport REX3",
        base_address=0xbf0f0000,
        size=0x10000,
        registers=REX3_REGISTERS,
        description="Newport Raster Engine (GIO64 Graphics)"
    ),
    # IP30 Octane devices
    "HEART": DeviceDef(
        name="Heart",
        base_address=0x0ff00000,
        size=0x100000,
        registers=HEART_REGISTERS,
        description="Heart System Controller (Octane IP30)"
    ),
    "XBOW": DeviceDef(
        name="Xbow",
        base_address=0x10000000,
        size=0x40000,
        registers=XBOW_REGISTERS,
        description="Crossbar Switch (Octane IP30)"
    ),
    "BRIDGE": DeviceDef(
        name="Bridge",
        base_address=0x0f000000,  # Typical widget space
        size=0x40000,
        registers=BRIDGE_REGISTERS,
        description="PCI-XIO Bridge (Octane IP30)"
    ),
}


def annotate_address(addr: int) -> Optional[Tuple[str, str, str]]:
    """
    Annotate a hardware address with device and register information.

    Returns:
        Tuple of (device_name, register_name, description) or None if unknown.
    """
    # Sort devices by size (smaller first) to check more specific regions first
    # This ensures IOC2 is checked before HPC3 since IOC2 is within HPC3's range
    sorted_devices = sorted(DEVICES.items(), key=lambda x: x[1].size)

    for device_id, device in sorted_devices:
        if device.base_address <= addr < device.base_address + device.size:
            offset = addr - device.base_address

            # Find matching register
            for reg in device.registers:
                if reg.offset <= offset < reg.offset + max(reg.size, 4):
                    return (device.name, reg.name, reg.description)

            # No specific register, but within device range
            return (device.name, f"+0x{offset:x}", f"Unknown register at offset 0x{offset:x}")

    # Check for known address ranges
    # GIO64 Graphics slot
    if 0xbf000000 <= addr < 0xbf400000:
        offset = addr - 0xbf000000
        return ("GIO64_GFX", f"+0x{offset:x}", "GIO64 Graphics slot")

    # GIO64 Expansion slot 0
    if 0xbf400000 <= addr < 0xbf600000:
        offset = addr - 0xbf400000
        return ("GIO64_EXP0", f"+0x{offset:x}", "GIO64 Expansion slot 0")

    # GIO64 Expansion slot 1
    if 0xbf600000 <= addr < 0xbfa00000:
        offset = addr - 0xbf600000
        return ("GIO64_EXP1", f"+0x{offset:x}", "GIO64 Expansion slot 1")

    # PROM area
    if 0xbfc00000 <= addr < 0xc0000000:
        offset = addr - 0xbfc00000
        return ("PROM", f"+0x{offset:x}", "Boot PROM")

    # Low memory (RAM alias)
    if 0xa0000000 <= addr < 0xa0080000:
        return ("RAM_LOW", f"+0x{addr - 0xa0000000:x}", "Low RAM (first 512KB)")

    # Main memory
    if 0xa8000000 <= addr < 0xb0000000:
        return ("RAM_MAIN", f"+0x{addr - 0xa8000000:x}", "Main RAM")

    # =============================================================================
    # IP30 Octane address ranges (Heart/Xbow architecture)
    # =============================================================================

    # Heart ASIC (Octane system controller)
    # Physical addresses in node space
    if 0x0ff00000 <= addr < 0x10000000:
        offset = addr - 0x0ff00000
        for reg in HEART_REGISTERS:
            if reg.offset <= offset < reg.offset + max(reg.size, 8):
                return ("Heart", reg.name, reg.description)
        return ("Heart", f"+0x{offset:x}", "Heart register")

    # Xbow widget space (crossbar)
    if 0x10000000 <= addr < 0x20000000:
        widget = (addr >> 24) & 0xf
        widget_offset = addr & 0xffffff
        for reg in XBOW_REGISTERS:
            if reg.offset <= widget_offset < reg.offset + max(reg.size, 4):
                return ("Xbow", f"W{widget:x}_{reg.name}", reg.description)
        return ("Xbow", f"Widget{widget:x}+0x{widget_offset:x}", f"XIO Widget {widget}")

    # XIO widget address space (general)
    # Widgets 8-F are at 0x9NNNNNNN or 0x1NNNNNNN where N is widget number
    if 0x90000000 <= addr < 0xa0000000:
        widget = (addr >> 24) & 0xf
        widget_offset = addr & 0xffffff
        return ("XIO", f"Widget{widget:x}+0x{widget_offset:x}", f"XIO Widget {widget} (cached)")

    # Bridge (PCI-XIO bridge) commonly at widget address
    if 0x0f000000 <= addr < 0x0ff00000:
        offset = addr - 0x0f000000
        for reg in BRIDGE_REGISTERS:
            if reg.offset <= offset < reg.offset + max(reg.size, 4):
                return ("Bridge", reg.name, reg.description)
        return ("Bridge", f"+0x{offset:x}", "PCI-XIO Bridge register")

    return None


def format_annotation(addr: int) -> str:
    """Format an address annotation as a string."""
    result = annotate_address(addr)
    if result:
        device, reg, desc = result
        return f"{device}.{reg} ; {desc}"
    return ""


def get_device_info(device_id: str) -> Optional[DeviceDef]:
    """Get device definition by ID."""
    return DEVICES.get(device_id)


def list_devices() -> List[str]:
    """List all known device IDs."""
    return list(DEVICES.keys())


def get_lui_annotation(imm: int) -> Optional[str]:
    """
    Annotate a LUI immediate value if it corresponds to a known device.

    Args:
        imm: The 16-bit immediate value from LUI instruction

    Returns:
        Annotation string or None
    """
    upper_addr = imm << 16

    # Check known base addresses (IP22/IP24 - GIO architecture)
    if upper_addr == 0xbfa00000:
        return "MC base"
    elif upper_addr == 0xbfb80000:
        return "HPC3 base"
    elif upper_addr == 0xbfbd0000:
        return "IOC2 area"
    elif upper_addr == 0xbf0f0000:
        return "REX3 base"
    elif upper_addr == 0xbf000000:
        return "GIO64 GFX"
    elif upper_addr == 0xbf400000:
        return "GIO64 EXP0"
    elif upper_addr == 0xbf600000:
        return "GIO64 EXP1"
    elif upper_addr == 0xbfc00000:
        return "PROM base"
    elif upper_addr == 0xa0000000:
        return "KSEG1 base"
    elif upper_addr == 0x80000000:
        return "KSEG0 base"

    # IP30 Octane addresses (Heart/Xbow architecture)
    elif upper_addr == 0x0ff00000:
        return "Heart base"
    elif upper_addr == 0x10000000:
        return "Xbow base"
    elif upper_addr == 0x0f000000:
        return "Bridge base"
    elif 0x90000000 <= upper_addr < 0xa0000000:
        widget = (upper_addr >> 24) & 0xf
        return f"XIO Widget {widget:x} (cached)"
    elif 0x10000000 <= upper_addr < 0x20000000:
        widget = (upper_addr >> 24) & 0xf
        return f"XIO Widget {widget:x} (uncached)"

    return None
