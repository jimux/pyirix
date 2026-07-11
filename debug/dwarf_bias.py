"""Per-CU text-bias recovery for SGI MIPS DWARF (.debug_info).

Campaign-4 A1: promote the bias-recovery logic proven across libc/libSgm/libXext
and the campaign-1 retro-harvest into a tested library function.

The problem (the "per-CU text-bias trap"): a DWARF `DW_AT_low_pc` recovered from
`.debug_info` may be UN-RELOCATED -- a link-time, per-CU (and, for C++
comdat/linkonce, per-SECTION) value rather than the final runtime address. Naive
`low_pc == FUN_addr` matching then produces a PLAUSIBLE map with every name shifted
onto the WRONG function -- a consistent substitution that passes renames-only,
collision, balance and placement checks yet is semantically wrong. Structural gates
cannot catch it; only address recovery + a semantic spot-check can.

The recovery: for each CU, the bias is `dynsym_addr - DIE_low_pc` measured on
globally-unique EXPORTED function anchors (a name that is unique in both the DWARF
and the dynsym). Data symbols (`DW_OP_addr`) carry ZERO bias -- verified across the
corpus -- so they need no recovery.

Two regimes, opposite reliability (retro-harvest lesson):
  * ZERO-BIAS: every anchor in the CU gives bias 0 -> address identity, SAFE. This
    is the dominant regime; campaign-1's "address-less DWARF, honest floor" verdicts
    on these were artifacts of the OLD lossy extractor, not real ceilings.
  * MULTI-SECTION: anchors give several distinct biases (a source CU split across
    link sections). Prefer the DOMINANT bias and REQUIRE a body/wiring spot-check;
    do NOT pool all candidate biases as equals -- a 46-way split makes pooled
    residue-hits abundant and spurious.
"""
from collections import defaultdict, Counter

from pyirix.debug.dwarf import DwarfParser


def _anchor_biases(funcs, func_exports):
    """Per-CU candidate biases from globally-unique exported anchors.

    funcs: DwarfParser.funcs() output (each has name, low_pc, linkage, cu).
    func_exports: {name: addr} of exported FUNC symbols (include BOTH the mangled
        and the demangled/bare spellings you have; the anchor match is by exact
        name). The export check MUST use the name that also appears in DWARF -- for
        C++, that is usually the mangled `linkage` name (matching on the demangled
        base lets an exported method anchor the wrong CU).
    Returns {cu: [biases, most-common-first]}.
    """
    # a name is a usable anchor only if it is unique among DWARF funcs AND unique
    # (present) in the export table.
    dwarf_name_count = Counter(f["name"] for f in funcs if f.get("name"))
    dwarf_link_count = Counter(f["linkage"] for f in funcs if f.get("linkage"))
    cu_anchor = defaultdict(list)
    for f in funcs:
        lp, cu = f.get("low_pc"), f.get("cu")
        if lp is None or cu is None:
            continue
        anchor = None
        mang, bare = f.get("linkage"), f.get("name")
        if mang and mang in func_exports and dwarf_link_count[mang] == 1:
            anchor = func_exports[mang]
        elif bare and bare in func_exports and dwarf_name_count[bare] == 1:
            anchor = func_exports[bare]
        if anchor is not None:
            cu_anchor[cu].append(anchor - lp)
    return {cu: [b for b, _ in Counter(bs).most_common()] for cu, bs in cu_anchor.items()}


def classify_cu(biases):
    """'zero-bias' (identity, safe) | 'biased' (single nonzero) | 'multi-section'."""
    if not biases:
        return "no-anchor"
    if biases == [0]:
        return "zero-bias"
    if len(biases) == 1:
        return "biased"
    return "multi-section"


def recover(binpath, func_exports, target_addrs):
    """Resolve DWARF-internal (pool) function DIEs to real addresses in target_addrs.

    binpath: the ELF with .debug_info.
    func_exports: {name: addr} exported FUNC symbols (mangled + bare spellings).
    target_addrs: set of ints -- the residue addresses you want to name (e.g. the
        int(x) of every FUN_<hex> still in the reconstruction). Only DIEs that land
        on one of these are returned.

    Returns (hits, cu_bias, stats):
      hits: [{name, linkage, real_addr, low_pc, cu, bias, regime}] -- each an
            accepted rename candidate. `regime` flags which trees still need a
            mandatory semantic spot-check ('multi-section'/'biased' do; 'zero-bias'
            is safe by address identity).
      cu_bias: {cu: [candidate biases]} audit table.
      stats: Counter of nobias / not_residue / ambiguous / accepted.
    """
    dp = DwarfParser(str(binpath))
    funcs = dp.funcs()
    cu_bias = _anchor_biases(funcs, func_exports)
    exported_names = set(func_exports)
    target = set(target_addrs)
    # a DIE address may be claimed by more than one accepted name -> drop the collision.
    claims = defaultdict(list)
    info = {}
    stats = Counter()
    for f in funcs:
        lp, cu = f.get("low_pc"), f.get("cu")
        name, mang = f.get("name"), f.get("linkage")
        if not name or lp is None or cu is None:
            continue
        # skip exported symbols -- those already carry real names; we name the pool.
        if name in exported_names or (mang and mang in exported_names):
            continue
        biases = cu_bias.get(cu)
        if not biases:
            stats["nobias"] += 1
            continue
        regime = classify_cu(biases)
        if regime == "multi-section":
            # dominant bias only (retro-harvest: pooling spurious for large splits),
            # but still require a UNIQUE landing to accept.
            cand = [biases[0]]
        else:
            cand = biases
        hits = sorted({lp + b for b in cand if (lp + b) in target})
        if not hits:
            stats["not_residue"] += 1
            continue
        if len(hits) > 1:
            stats["ambiguous"] += 1
            continue
        ra = hits[0]
        claims[ra].append(name)
        info[ra] = {"name": name, "linkage": mang, "real_addr": ra, "low_pc": lp,
                    "cu": cu, "bias": ra - lp, "regime": regime}
    out = []
    for ra, names in claims.items():
        if len(names) == 1:
            out.append(info[ra])
            stats["accepted"] += 1
        else:
            stats["addr_collision"] += 1
    return out, cu_bias, stats
