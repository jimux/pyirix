#!/usr/bin/env python3
"""
Prepend an SGI volume header to a raw EFS image so IRIX's dksc driver
will recognize it as a partitioned disk and create /dev/dsk/dks0d2s7.

Layout:
  Disk sector 0       : SGI Volume Header (512 bytes)
  Disk sectors 1+     : Raw EFS filesystem image

Partition table:
  pt[0]  volhdr : firstlbn=0,  nblks=1      (just the VH sector)
  pt[6]  volume : firstlbn=0,  nblks=total  (whole disk)
  pt[7]  efs    : firstlbn=1,  nblks=efs_sectors (EFS data)
"""
import sys
import os
sys.path.insert(0, 'analysis_tools')
from analysis_tools.create_boot_disk import build_vh, SECTOR_SIZE, PTYPE_VOLHDR, PTYPE_VOLUME, PTYPE_EFS

EFS_PATH = 'kern_src.efs.img'
OUT_PATH = 'kern_src_disk.img'

efs_data = open(EFS_PATH, 'rb').read()
efs_sectors = (len(efs_data) + SECTOR_SIZE - 1) // SECTOR_SIZE
total_sectors = 1 + efs_sectors  # VH sector + EFS sectors

pt_entries = [None] * 16
for i in range(16):
    pt_entries[i] = {'nblks': 0, 'firstlbn': 0, 'type': 0}

pt_entries[0] = {'nblks': 1,            'firstlbn': 0, 'type': PTYPE_VOLHDR}  # VH
pt_entries[6] = {'nblks': total_sectors, 'firstlbn': 0, 'type': PTYPE_VOLUME}  # whole disk
pt_entries[7] = {'nblks': efs_sectors,  'firstlbn': 1, 'type': PTYPE_EFS}     # EFS data

vh_bytes = build_vh(bootfile='', vd_entries=[], pt_entries=pt_entries)
assert len(vh_bytes) == SECTOR_SIZE

with open(OUT_PATH, 'wb') as f:
    f.write(vh_bytes)        # sector 0: VH
    f.write(efs_data)        # sectors 1+: EFS

print(f"Created {OUT_PATH}: {total_sectors} sectors "
      f"({total_sectors * SECTOR_SIZE // (1024*1024)} MB)")
print(f"  pt[0] volhdr: 0 .. 0  (1 sector)")
print(f"  pt[6] volume: 0 .. {total_sectors-1}  ({total_sectors} sectors)")
print(f"  pt[7] efs:    1 .. {efs_sectors}  ({efs_sectors} sectors)")
