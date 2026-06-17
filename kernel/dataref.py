#!/usr/bin/env python3
"""Find where a kernel address is referenced: as a stored 4-byte data word
(function pointer in a struct/table) and as lui/ori|addiu immediate loads."""
import json, struct, sys, bisect, os
ELF=os.environ.get("KELF","/workspace/_golden_extract/unix"); SYMS=os.environ.get("KSYMS","/workspace/ip54_kernel_symbols_golden.json")
target=int(sys.argv[1],0)
d=open(ELF,"rb").read()
is64=d[4]==2
shoff=struct.unpack(">Q",d[0x28:0x30])[0] if is64 else struct.unpack(">I",d[0x20:0x24])[0]
es=struct.unpack(">H",d[(0x3a if is64 else 0x2e):(0x3c if is64 else 0x30)])[0]
n=struct.unpack(">H",d[(0x3c if is64 else 0x30):(0x3e if is64 else 0x32)])[0]
secs=[]
for i in range(n):
    e=d[shoff+i*es:shoff+(i+1)*es]
    if is64: addr=struct.unpack(">Q",e[0x10:0x18])[0]; off=struct.unpack(">Q",e[0x18:0x20])[0]; sz=struct.unpack(">Q",e[0x20:0x28])[0]
    else: addr=struct.unpack(">I",e[0x0c:0x10])[0]; off=struct.unpack(">I",e[0x10:0x14])[0]; sz=struct.unpack(">I",e[0x14:0x18])[0]
    secs.append((addr&0xffffffff,off,sz))
syms=json.load(open(SYMS))
funcs=sorted((s["address"]&0xffffffff,s["name"]) for s in syms if s.get("type")=="FUNC")
objs=sorted((s["address"]&0xffffffff,s["name"]) for s in syms if s.get("type")=="OBJECT")
fa=[a for a,_ in funcs]; oa=[a for a,_ in objs]
def encl(pc,tbl,addrs):
    i=bisect.bisect_right(addrs,pc)-1
    if i<0: return "?"
    base,nm=tbl[i]; return f"{nm}+0x{pc-base:x}" if pc!=base else nm
tb=struct.pack(">I",target&0xffffffff)
print(f"=== references to 0x{target:08x} ===")
print("-- as stored 4-byte data word (function-pointer table/struct) --")
for base,off,sz in secs:
    if base==0 or sz==0: continue
    blob=d[off:off+sz]; idx=0
    while True:
        j=blob.find(tb,idx)
        if j<0: break
        if j%4==0:
            va=base+j
            loc=encl(va,objs,oa) if oa else "?"
            locf=encl(va,funcs,fa)
            print(f"  data@0x{va:08x}  (obj:{loc}) (near func:{locf})")
        idx=j+1
