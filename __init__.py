"""pyirix — Python library for SGI/IRIX disc images, filesystems, and binaries.

Subpackages:
  pyirix.efs    — Read and extract SGI EFS filesystem images
  pyirix.xfs    — Read and write SGI XFS filesystems (IRIX 6.x system disks)
  pyirix.dist   — Parse and analyze IRIX distribution packages and spec files
  pyirix.debug  — Static ELF analysis + a live gdb-multiarch driver for the guest

The filesystem and distribution tools are pure standard library; only
pyirix.debug.guest_gdb talks to a running QEMU guest.
"""
