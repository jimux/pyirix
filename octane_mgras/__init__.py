"""The Octane (IP30) MGRAS RE4/VC3 register map, and the instruments that derive it.

The map is a repo artifact because the ticket folder it was first produced in is
deleted when the effort closes (charter rule 11).  Two consecutive tickets lost
theirs that way; this package is where the map lives so the next ticket can open
it.

WHAT IS HERE, AND WHAT EACH PART IS FOR

  re4_registers.json   one entry per register the traced path touches:
                       `offset`, `width`, `dir`, `name`, `model_state`,
                       `evidence`, `writer_functions`, `block`, `role`, `note`
  access_sequence.json the same trace, as the offsets and counts the coverage
                       fraction is a fraction OF (`counts`, `sizes`,
                       `first_touch_order`, `triggers`, `window`)
  attr_offsets.py      widget-base dataflow over a disassembly: which kernel
                       function computes a widget offset (the naming witness)
  model_state.py       does the model implement the offset, and in which of the
                       FOUR handler forms (direct, `BASE + OFF`, the CMAP/DAC
                       window form `off - BASE == OFF`, and a `switch case`)
  access_seq.py        the model's write trace -> access_sequence.json
  build_map.py         the two JSON inputs + the disassembly + the model tree ->
                       re4_registers.json, with every citation re-resolved

RE-DERIVING IT

    python -m pyirix.octane_mgras.reproduce --check    # the committed artifact
    python -m pyirix.octane_mgras.reproduce --full     # needs the trace

`--check` re-reads the two committed JSONs and re-runs both controls against the
committed fixture, so it answers "is the map still consistent with its own
witnesses" with no VM, no golden, no 195 MB trace.  `--full` additionally
re-disassembles `/unix` and re-derives every citation, which is what a model
change should run before trusting the `model_state` column.
"""
