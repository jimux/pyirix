#!/usr/bin/env python3
"""pyirix.indigo — the Indigo-Magic-on-Linux asset importer.

Bring-your-own IRIX media → an IRIX-shaped data root the native port reads
(schemes, fonts, filetype/FTR, iconcatalog, app-defaults, sounds, savers).

Public entry points:
    from pyirix.indigo.importer import run_import
    from pyirix.indigo.verify   import verify
    from pyirix.indigo.sources  import open_source
    from pyirix.indigo.config   import resolve_data_root

CLI:
    python3 -m pyirix.indigo import <source>... [--dest DIR]
    python3 -m pyirix.indigo verify [--dest DIR]
"""

from pyirix.indigo.manifest import MANIFEST, ManifestEntry

__all__ = ["MANIFEST", "ManifestEntry"]
