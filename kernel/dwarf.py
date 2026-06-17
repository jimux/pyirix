#!/usr/bin/env python3
"""dwarf_types — minimal from-scratch DWARF2 (.debug_abbrev + .debug_info) parser
for SGI MIPS_DWARF binaries that pyelftools' DIE parser can't handle (it chokes on
SGI-specific attrs like DW_AT 0x2001). Recovers struct/union LAYOUTS, function
SIGNATURES, typedefs, enums — ground truth for RE.

  python3 dwarf_types.py <elf> struct <name>     # one struct's members
  python3 dwarf_types.py <elf> func <name>        # one function's signature
  python3 dwarf_types.py <elf> structs [substr]   # list structs (opt. filter)
  python3 dwarf_types.py <elf> json <out.json>    # dump all structs+funcs to JSON

Big-endian assumed (IRIX MIPS). Standard DWARF2 forms; unknown attrs skipped by form.
"""
import sys, struct, json

# ---- form sizes / readers (DWARF2) ----
DW_TAG = {0x11:"compile_unit",0x2e:"subprogram",0x05:"formal_parameter",
          0x34:"variable",0x13:"structure_type",0x17:"union_type",0x0d:"member",
          0x16:"typedef",0x24:"base_type",0x0f:"pointer_type",0x01:"array_type",
          0x21:"subrange_type",0x26:"const_type",0x35:"volatile_type",
          0x04:"enumeration_type",0x28:"enumerator",0x15:"subroutine_type",
          0x18:"unspecified_parameters"}
# attrs we care about
AT_name=0x03; AT_byte_size=0x0b; AT_type=0x49; AT_member_loc=0x38
AT_encoding=0x3e; AT_const_value=0x1c; AT_upper_bound=0x2f; AT_prototyped=0x27
AT_external=0x3f; AT_low_pc=0x11


def uleb(b, p):
    r = 0; s = 0
    while True:
        x = b[p]; p += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, p
        s += 7


def sleb(b, p):
    r = 0; s = 0
    while True:
        x = b[p]; p += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            if x & 0x40:
                r |= -(1 << s)
            return r, p


def load_sections(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF"
    is64 = d[4] == 2
    be = d[5] == 2
    e = ">" if be else "<"
    if is64:
        shoff = struct.unpack(e+"Q", d[0x28:0x30])[0]
        shentsize = struct.unpack(e+"H", d[0x3a:0x3c])[0]
        shnum = struct.unpack(e+"H", d[0x3c:0x3e])[0]
        shstrndx = struct.unpack(e+"H", d[0x3e:0x40])[0]
    else:
        shoff = struct.unpack(e+"I", d[0x20:0x24])[0]
        shentsize = struct.unpack(e+"H", d[0x2e:0x30])[0]
        shnum = struct.unpack(e+"H", d[0x30:0x32])[0]
        shstrndx = struct.unpack(e+"H", d[0x32:0x34])[0]
    secs = []
    for i in range(shnum):
        o = shoff + i*shentsize
        nameoff = struct.unpack(e+"I", d[o:o+4])[0]
        if is64:
            addr = struct.unpack(e+"Q", d[o+16:o+24])[0]
            off = struct.unpack(e+"Q", d[o+24:o+32])[0]
            sz = struct.unpack(e+"Q", d[o+32:o+40])[0]
        else:
            addr = struct.unpack(e+"I", d[o+12:o+16])[0]
            off = struct.unpack(e+"I", d[o+16:o+20])[0]
            sz = struct.unpack(e+"I", d[o+20:o+24])[0]
        secs.append((nameoff, off, sz))
    stoff = secs[shstrndx][1]
    def nm(o):
        en = d.index(b"\0", stoff+o)
        return d[stoff+o:en].decode("latin1")
    out = {}
    for nameoff, off, sz in secs:
        out[nm(nameoff)] = d[off:off+sz]
    out["__be__"] = be
    return out


class DwarfParser:
    def __init__(self, path):
        s = load_sections(path)
        self.be = s["__be__"]
        self.e = ">" if self.be else "<"
        self.info = s.get(".debug_info", b"")
        self.abbrev = s.get(".debug_abbrev", b"")
        self.dies = {}       # global .debug_info offset -> die dict
        self._parse()

    def _u(self, n, p):
        v = struct.unpack(self.e + {1:"B",2:"H",4:"I",8:"Q"}[n], self.info[p:p+n])[0]
        return v, p+n

    def _abbrev_table(self, start):
        # NOTE: SGI MIPS_DWARF abbrev tables are NOT null-terminated — each CU's
        # abbrev_off points at its own table and codes reset to 1 at the next table.
        # So stop on a null code OR when the code resets (<= previous code).
        tbl = {}; p = start; A = self.abbrev; prev = 0
        while p < len(A):
            code, p = uleb(A, p)
            if code == 0 or code <= prev:
                break
            prev = code
            tag, p = uleb(A, p)
            hc = A[p]; p += 1
            attrs = []
            while True:
                at, p = uleb(A, p); fm, p = uleb(A, p)
                if at == 0 and fm == 0:
                    break
                attrs.append((at, fm))
            tbl[code] = (tag, hc, attrs)
        return tbl

    def _read_form(self, fm, p, cu_start, addr_size):
        """Return (value, new_p). value: int|str|('ref',global_off)|bytes."""
        info = self.info
        if fm == 0x01:  # addr
            return self._u(addr_size, p)
        if fm == 0x03:  # block2
            n, p = self._u(2, p); return info[p:p+n], p+n
        if fm == 0x04:  # block4
            n, p = self._u(4, p); return info[p:p+n], p+n
        if fm == 0x05:  # data2
            return self._u(2, p)
        if fm == 0x06:  # data4
            return self._u(4, p)
        if fm == 0x07:  # data8
            return self._u(8, p)
        if fm == 0x08:  # string
            en = info.index(b"\0", p); return info[p:en].decode("latin1"), en+1
        if fm == 0x09:  # block (uleb len)
            n, p = uleb(info, p); return info[p:p+n], p+n
        if fm == 0x0a:  # block1
            n = info[p]; p += 1; return info[p:p+n], p+n
        if fm == 0x0b:  # data1
            return self._u(1, p)
        if fm == 0x0c:  # flag
            return self._u(1, p)
        if fm == 0x0d:  # sdata
            return sleb(info, p)
        if fm == 0x0e:  # strp (we don't keep .debug_str; return offset)
            v, p = self._u(4, p); return ("strp", v), p
        if fm == 0x0f:  # udata
            return uleb(info, p)
        if fm == 0x10:  # ref_addr (global)
            v, p = self._u(4, p); return ("ref", v), p
        if fm == 0x11:  # ref1
            v, p = self._u(1, p); return ("ref", cu_start+v), p
        if fm == 0x12:  # ref2
            v, p = self._u(2, p); return ("ref", cu_start+v), p
        if fm == 0x13:  # ref4
            v, p = self._u(4, p); return ("ref", cu_start+v), p
        if fm == 0x14:  # ref8
            v, p = self._u(8, p); return ("ref", cu_start+v), p
        if fm == 0x15:  # ref_udata
            v, p = uleb(info, p); return ("ref", cu_start+v), p
        if fm == 0x16:  # indirect
            fm2, p = uleb(info, p); return self._read_form(fm2, p, cu_start, addr_size)
        raise ValueError("unknown form 0x%x at 0x%x" % (fm, p))

    def _parse(self):
        info = self.info; p = 0
        while p < len(info):
            cu_start = p
            unit_len, p = self._u(4, p)
            cu_end = p + unit_len
            ver, p = self._u(2, p)
            abbrev_off, p = self._u(4, p)
            addr_size = info[p]; p += 1
            tbl = self._abbrev_table(abbrev_off)
            stack = []  # parent offsets for children nesting
            while p < cu_end:
                die_off = p
                code, p = uleb(info, p)
                if code == 0:        # end of children
                    if stack:
                        stack.pop()
                    continue
                tag, hc, attrs = tbl[code]
                die = {"off": die_off, "tag": tag, "tag_name": DW_TAG.get(tag, "t%#x" % tag),
                       "attrs": {}, "children": [], "parent": stack[-1] if stack else None}
                for at, fm in attrs:
                    val, p = self._read_form(fm, p, cu_start, addr_size)
                    die["attrs"][at] = val
                self.dies[die_off] = die
                if die["parent"] is not None:
                    self.dies[die["parent"]]["children"].append(die_off)
                if hc:
                    stack.append(die_off)
            p = cu_end

    # ---- type name resolution ----
    def type_name(self, ref, depth=0):
        if ref is None or depth > 12:
            return "void" if ref is None else "?"
        if isinstance(ref, tuple) and ref[0] == "ref":
            off = ref[1]
        else:
            return "?"
        die = self.dies.get(off)
        if not die:
            return "?"
        t = die["tag"]
        a = die["attrs"]
        if t == 0x24 or t == 0x16:                       # base_type / typedef
            return a.get(AT_name, "?")
        if t == 0x13:
            return "struct " + a.get(AT_name, "anon")
        if t == 0x17:
            return "union " + a.get(AT_name, "anon")
        if t == 0x04:
            return "enum " + a.get(AT_name, "anon")
        if t == 0x0f:                                    # pointer
            return self.type_name(a.get(AT_type), depth+1) + " *"
        if t == 0x26:                                    # const
            return "const " + self.type_name(a.get(AT_type), depth+1)
        if t == 0x35:                                    # volatile
            return "volatile " + self.type_name(a.get(AT_type), depth+1)
        if t == 0x01:                                    # array
            return self.type_name(a.get(AT_type), depth+1) + "[]"
        if t == 0x15:                                    # subroutine
            return self.type_name(a.get(AT_type), depth+1) + " (*)()"
        return a.get(AT_name, die["tag_name"])

    def member_offset(self, die):
        v = die["attrs"].get(AT_member_loc)
        if v is None:
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, bytes):
            # DWARF expr: DW_OP_plus_uconst (0x23) <uleb>, or DW_OP_constN
            if v and v[0] == 0x23:
                off, _ = uleb(v, 1); return off
            if v and v[0] == 0x08:   # const1
                return v[1]
        return None

    def structs(self):
        out = []
        for off, die in self.dies.items():
            if die["tag"] in (0x13, 0x17):
                out.append(die)
        return out

    def struct_layout(self, die):
        a = die["attrs"]
        members = []
        for c in die["children"]:
            cd = self.dies[c]
            if cd["tag"] != 0x0d:
                continue
            members.append({"name": cd["attrs"].get(AT_name, "?"),
                            "offset": self.member_offset(cd),
                            "type": self.type_name(cd["attrs"].get(AT_type))})
        return {"name": a.get(AT_name, "anon"),
                "kind": "union" if die["tag"] == 0x17 else "struct",
                "size": a.get(AT_byte_size), "members": members}

    def variables(self):
        """Global variables: name + address (from DW_OP_addr location)."""
        out = []
        for off, die in self.dies.items():
            if die["tag"] != 0x34 or AT_name not in die["attrs"]:
                continue
            loc = die["attrs"].get(0x02)
            addr = None
            if isinstance(loc, bytes) and loc and loc[0] == 0x03:   # DW_OP_addr
                addr = struct.unpack(self.e + "I", loc[1:5])[0]
            out.append({"name": die["attrs"][AT_name], "addr": addr,
                        "type": self.type_name(die["attrs"].get(AT_type))})
        return out

    def funcs(self):
        out = []
        for off, die in self.dies.items():
            if die["tag"] == 0x2e and AT_name in die["attrs"]:
                params = []
                for c in die["children"]:
                    cd = self.dies[c]
                    if cd["tag"] == 0x05:
                        params.append({"name": cd["attrs"].get(AT_name, ""),
                                       "type": self.type_name(cd["attrs"].get(AT_type))})
                    elif cd["tag"] == 0x18:
                        params.append({"name": "...", "type": ""})
                out.append({"name": die["attrs"][AT_name],
                            "ret": self.type_name(die["attrs"].get(AT_type)),
                            "params": params})
        return out


def fmt_struct(s):
    lines = ["%s %s {  /* size %s */" % (s["kind"], s["name"], s["size"])]
    for m in s["members"]:
        off = m["offset"]
        lines.append("    %-24s %-18s /* +%s */" % (m["type"], m["name"] + ";",
                     ("0x%x" % off) if off is not None else "?"))
    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print(__doc__); return
    elf = sys.argv[1]; cmd = sys.argv[2]
    dp = DwarfParser(elf)
    if cmd == "struct":
        want = sys.argv[3]
        for d in dp.structs():
            if d["attrs"].get(AT_name) == want:
                print(fmt_struct(dp.struct_layout(d))); return
        print("struct %s not found" % want)
    elif cmd == "structs":
        sub = sys.argv[3] if len(sys.argv) > 3 else ""
        seen = set()
        for d in dp.structs():
            n = d["attrs"].get(AT_name)
            if n and sub in n and n not in seen:
                seen.add(n)
                print("  %-30s size=%s members=%d" % (n, d["attrs"].get(AT_byte_size),
                      len(dp.struct_layout(d)["members"])))
        print("total distinct structs:", len(seen))
    elif cmd == "func":
        want = sys.argv[3]
        for f in dp.funcs():
            if f["name"] == want:
                args = ", ".join("%s %s" % (p["type"], p["name"]) for p in f["params"]) or "void"
                print("%s %s(%s);" % (f["ret"], f["name"], args)); return
        print("func %s not found" % want)
    elif cmd == "vars":
        sub = sys.argv[3] if len(sys.argv) > 3 else ""
        for v in sorted(dp.variables(), key=lambda x: x["addr"] or 0):
            if sub in v["name"]:
                print("  0x%08x  %s" % (v["addr"] or 0, v["name"]))
    elif cmd == "json":
        out = sys.argv[3]
        structs = {}
        for d in dp.structs():
            n = d["attrs"].get(AT_name)
            if n:
                structs[n] = dp.struct_layout(d)
        json.dump({"structs": structs, "funcs": dp.funcs()}, open(out, "w"))
        print("wrote %d structs, %d funcs -> %s" % (len(structs), len(dp.funcs()), out))


if __name__ == "__main__":
    main()
