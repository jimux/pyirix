# SGI PROM Comparative Analysis - MIPS Disassembler
"""
MIPS disassembly with hardware annotations using Capstone.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import struct

try:
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from pyirix.prom.config import PROM_BASE, prom_offset_to_addr, addr_to_prom_offset
from pyirix.prom.hardware_defs import annotate_address, format_annotation, get_lui_annotation
from pyirix.prom.prom_loader import load_prom, get_prom_metadata, normalize_data


@dataclass
class DisasmLine:
    """A single disassembled instruction."""
    address: int
    offset: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    annotation: str = ""
    is_branch: bool = False
    branch_target: Optional[int] = None


@dataclass
class LuiTracker:
    """Tracks LUI instructions for address reconstruction."""
    register: str
    value: int
    address: int


class MipsDisassembler:
    """MIPS disassembler with SGI hardware annotations."""

    def __init__(self, mode: str = "mips3"):
        if not CAPSTONE_AVAILABLE:
            raise RuntimeError("Capstone library not available. Install with: pip install capstone")

        # Select mode based on CPU architecture
        if mode in ("mips1", "mips2"):
            cs_mode = CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN
        else:
            cs_mode = CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN

        self.cs = Cs(CS_ARCH_MIPS, cs_mode)
        self.cs.detail = True

        # Track LUI instructions for address reconstruction
        self.lui_values: Dict[str, LuiTracker] = {}

    def disassemble(
        self,
        data: bytes,
        base_address: int = PROM_BASE,
        max_instructions: int = 0,
        annotate: bool = True
    ) -> List[DisasmLine]:
        """
        Disassemble MIPS binary data.

        Args:
            data: Binary data to disassemble
            base_address: Base address for disassembly
            max_instructions: Maximum instructions (0 = all)
            annotate: Add hardware annotations

        Returns:
            List of DisasmLine objects
        """
        lines = []
        count = 0

        for insn in self.cs.disasm(data, base_address):
            offset = insn.address - base_address

            bytes_hex = insn.bytes.hex()
            mnemonic = insn.mnemonic
            op_str = insn.op_str

            annotation = ""
            is_branch = False
            branch_target = None

            if annotate:
                annotation = self._annotate_instruction(insn)

            # Detect branch/jump instructions
            if mnemonic in ('b', 'beq', 'bne', 'bgtz', 'blez', 'bltz', 'bgez',
                           'j', 'jal', 'jr', 'jalr', 'beql', 'bnel'):
                is_branch = True
                branch_target = self._extract_branch_target(insn)

            lines.append(DisasmLine(
                address=insn.address,
                offset=offset,
                bytes_hex=bytes_hex,
                mnemonic=mnemonic,
                op_str=op_str,
                annotation=annotation,
                is_branch=is_branch,
                branch_target=branch_target
            ))

            count += 1
            if max_instructions > 0 and count >= max_instructions:
                break

        return lines

    def _annotate_instruction(self, insn) -> str:
        """Generate annotation for an instruction."""
        mnemonic = insn.mnemonic
        op_str = insn.op_str

        # Track LUI for address reconstruction
        if mnemonic == "lui":
            parts = op_str.split(",")
            if len(parts) == 2:
                reg = parts[0].strip()
                try:
                    imm = int(parts[1].strip(), 0)
                    self.lui_values[reg] = LuiTracker(reg, imm, insn.address)

                    # Check if this is a known base address
                    lui_ann = get_lui_annotation(imm)
                    if lui_ann:
                        return f"; {lui_ann}"
                except ValueError:
                    pass

        # Check load/store with register offset for hardware access
        if mnemonic in ('lw', 'sw', 'lh', 'sh', 'lb', 'sb', 'ld', 'sd', 'lwu', 'lhu', 'lbu'):
            # Parse "rt, offset(rs)" format
            import re
            match = re.match(r'(\$\w+),\s*(-?\w+)\((\$\w+)\)', op_str)
            if match:
                rt, offset_str, rs = match.groups()
                try:
                    offset = int(offset_str, 0)

                    # Check if we have a LUI value for this register
                    if rs in self.lui_values:
                        lui = self.lui_values[rs]
                        full_addr = (lui.value << 16) + offset
                        if full_addr < 0:
                            full_addr += 0x100000000  # Handle sign extension

                        annotation = format_annotation(full_addr)
                        if annotation:
                            return f"; 0x{full_addr:08x} {annotation}"
                        else:
                            return f"; 0x{full_addr:08x}"
                except ValueError:
                    pass

        # Annotate ORI/ADDIU that complete address formation
        if mnemonic in ('ori', 'addiu'):
            parts = op_str.replace(",", " ").split()
            if len(parts) >= 3:
                rt = parts[0]
                rs = parts[1]
                try:
                    imm = int(parts[2], 0)

                    if rs in self.lui_values:
                        lui = self.lui_values[rs]
                        if mnemonic == "ori":
                            full_addr = (lui.value << 16) | (imm & 0xffff)
                        else:  # addiu
                            full_addr = (lui.value << 16) + imm
                            if full_addr < 0:
                                full_addr += 0x100000000

                        annotation = format_annotation(full_addr)
                        if annotation:
                            return f"; = 0x{full_addr:08x} {annotation}"

                        # Update LUI tracking if result goes to different register
                        if rt != rs:
                            self.lui_values[rt] = LuiTracker(rt, full_addr >> 16, insn.address)
                except ValueError:
                    pass

        # Annotate JAL targets
        if mnemonic == "jal":
            try:
                target = int(op_str, 0)
                prom_offset = addr_to_prom_offset(target)
                if prom_offset is not None:
                    return f"; PROM+0x{prom_offset:x}"
            except ValueError:
                pass

        return ""

    def _extract_branch_target(self, insn) -> Optional[int]:
        """Extract branch/jump target address."""
        mnemonic = insn.mnemonic

        if mnemonic in ('jr', 'jalr'):
            return None  # Register-based, can't determine statically

        try:
            # For J/JAL, target is absolute (shifted)
            if mnemonic in ('j', 'jal'):
                return int(insn.op_str, 0)

            # For branches, target is PC-relative
            # Capstone gives us the resolved address
            parts = insn.op_str.split(",")
            if len(parts) >= 2:
                return int(parts[-1].strip(), 0)
        except ValueError:
            pass

        return None

    def reset_lui_tracking(self):
        """Reset LUI tracking state."""
        self.lui_values.clear()


def disassemble_prom(
    filename: str,
    offset: int = 0,
    length: int = 0,
    max_instructions: int = 100,
    annotate: bool = True
) -> List[DisasmLine]:
    """
    Disassemble a PROM file.

    Args:
        filename: PROM filename
        offset: Start offset within PROM
        length: Number of bytes to disassemble (0 = to end or max_instructions)
        max_instructions: Maximum instructions to disassemble
        annotate: Add hardware annotations

    Returns:
        List of DisasmLine objects
    """
    data = load_prom(filename)
    if not data:
        return []

    meta = get_prom_metadata(filename)
    if not meta:
        return []

    # Normalize to big-endian if needed
    if meta.endian != "big":
        data = normalize_data(data, meta.endian)

    # Calculate range
    start = offset
    if length > 0:
        end = min(start + length, len(data))
    else:
        end = len(data)

    # Slice data
    data_slice = data[start:end]
    base_addr = prom_offset_to_addr(start)

    # Get platform-appropriate mode
    mode = "mips3"  # Default
    if meta.platform:
        from pyirix.prom.config import get_cpu_mode
        mode = get_cpu_mode(meta.platform)

    disasm = MipsDisassembler(mode)
    return disasm.disassemble(data_slice, base_addr, max_instructions, annotate)


def format_disassembly(lines: List[DisasmLine], show_bytes: bool = True) -> str:
    """
    Format disassembly output.

    Args:
        lines: List of DisasmLine objects
        show_bytes: Include hex bytes in output

    Returns:
        Formatted string
    """
    result = []

    for line in lines:
        if show_bytes:
            text = f"{line.address:08x}  {line.bytes_hex:8s}  {line.mnemonic:8s} {line.op_str}"
        else:
            text = f"{line.address:08x}  {line.mnemonic:8s} {line.op_str}"

        if line.annotation:
            text = f"{text:50s} {line.annotation}"

        result.append(text)

    return "\n".join(result)


def find_function_prologues(data: bytes, base_address: int = PROM_BASE) -> List[Tuple[int, int]]:
    """
    Find function prologues in MIPS code.

    Looks for: addiu $sp, $sp, -N (where N > 0)

    Args:
        data: Binary data to search
        base_address: Base address

    Returns:
        List of (address, stack_frame_size) tuples
    """
    prologues = []

    # MIPS ADDIU $sp, $sp, -N encoding:
    # 0010 01ss ssst tttt iiii iiii iiii iiii
    # s = 29 (sp), t = 29 (sp), i = negative immediate
    # Opcode 0x09, rs=29, rt=29

    for i in range(0, len(data) - 3, 4):
        word = struct.unpack(">I", data[i:i + 4])[0]

        opcode = (word >> 26) & 0x3f
        rs = (word >> 21) & 0x1f
        rt = (word >> 16) & 0x1f
        imm = word & 0xffff

        # Check for ADDIU $sp, $sp, negative
        if opcode == 0x09 and rs == 29 and rt == 29:
            # Sign extend immediate
            if imm & 0x8000:
                imm_signed = imm - 0x10000
                if imm_signed < 0:
                    stack_size = -imm_signed
                    addr = base_address + i
                    prologues.append((addr, stack_size))

    return prologues


def find_function_at(data: bytes, address: int, base_address: int = PROM_BASE) -> Optional[Tuple[int, int]]:
    """
    Find function boundaries containing an address.

    Args:
        data: Binary data
        address: Address to find function for
        base_address: Base address

    Returns:
        (start_address, end_address) or None
    """
    prologues = find_function_prologues(data, base_address)

    # Sort prologues by address
    prologues.sort()

    # Find prologue before target address
    func_start = None
    for addr, _ in prologues:
        if addr <= address:
            func_start = addr
        else:
            break

    if func_start is None:
        return None

    # Find next prologue or end of data
    func_end = base_address + len(data)
    for addr, _ in prologues:
        if addr > func_start:
            func_end = addr
            break

    return (func_start, func_end)
