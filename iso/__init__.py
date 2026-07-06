"""ISO9660 CD image tools.

The EFS/XFS readers in pyirix handle SGI-native disc images, but several SGI demo
CDs are plain ISO9660 (e.g. "Maximum IMPACT Demos 96.iso", the Onyx2 demo ISO).
This package wraps a host extraction tool so ISO images can be unpacked with the
same `extract_recursive(dest_dir)` shape as `pyirix.efs`.
"""
from pyirix.iso.extract import (
    extract_recursive,
    list_recursive,
    iso_volume_id,
    available_backend,
)

__all__ = [
    "extract_recursive",
    "list_recursive",
    "iso_volume_id",
    "available_backend",
]
