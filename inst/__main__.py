"""``python -m pyirix.inst`` — run the ported installer CLI."""

import sys

from pyirix.inst.cli import main

if __name__ == "__main__":
    sys.exit(main())
