"""pyirix.inst — a Linux port of the IRIX ``inst`` software installer.

Part of the Indigo Magic Linux effort (document of record:
``progress_notes/indigo_distro/05-d4-inst-installer.md``).

IRIX's ``inst`` installs software from SGI **distributions**: directories of
products, each product a binary spec file (``pd001`` magic) + an install
descriptor (``<product>.idb``) + LZW archives (``<product>.sw``, ...).  This
package is a native rebuild of the tool for Linux: the media layer reuses the
proven ``pyirix.dist`` engine (idb/spec parsing, archive extraction, tardist
recursion), the behavioral oracle is the RE corpus
(``progress_notes/binary_re/inst`` + ``binary_re/libinst``), and the
transaction/target layer is new code with a pluggable destination
(tree / Linux disk / IRIX image).

Milestone state (see the doc of record):

* **M1 (this)**: stock option surface (byte-gated against the RE oracle),
  ``MediaSource`` product discovery, ``InstallPlan`` JSON (dry-run).
* **M2**: selection sets + dependency/conflict engine, ``TreeTarget``,
  curses TTY UI.
* **M3**: ``LinuxTarget`` — the D4 installer for Indigo Magic Linux.
* **M4**: GRUB wiring + ``indigo-inst`` deb + CI mode.
"""

__version__ = "0.1.0"

from pyirix.inst.media import DistError, MediaSource, Product
from pyirix.inst.plan import InstallFile, InstallPlan, build_plan

__all__ = [
    "DistError",
    "InstallFile",
    "InstallPlan",
    "MediaSource",
    "Product",
    "build_plan",
    "__version__",
]
