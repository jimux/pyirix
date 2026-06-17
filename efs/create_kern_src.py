#!/usr/bin/env python3
"""
Package irix-655-source/f/irix/kern/ into an EFS disk image.
The image is attached as a read-only SCSI disk inside IRIX and mounted
to provide the kernel source for the cooperative real-time clock patch.
"""
import os
import sys

sys.path.insert(0, 'analysis_tools')
from tar2efs import EFSBuilder

SRC_ROOT  = 'software_library/irix-655-source/f/irix/kern'
GUEST_ROOT = '/kern_src'
OUTPUT     = 'kern_src.efs.img'
SIZE_MB    = 128

print(f"Building EFS image from {SRC_ROOT} ...")
builder = EFSBuilder(size_mb=SIZE_MB)

file_count = 0
dir_count  = 0

for dirpath, dirnames, filenames in os.walk(SRC_ROOT):
    rel = os.path.relpath(dirpath, SRC_ROOT)
    if rel == '.':
        guest_dir = GUEST_ROOT
    else:
        guest_dir = f"{GUEST_ROOT}/{rel}"

    try:
        st = os.stat(dirpath)
    except OSError:
        continue

    builder.add_directory(guest_dir, st.st_mode & 0o777 | 0o40000, 0, 0, int(st.st_mtime))
    dir_count += 1

    for fname in sorted(filenames):
        fpath = os.path.join(dirpath, fname)
        gpath = f"{guest_dir}/{fname}"
        try:
            st = os.stat(fpath)
            with open(fpath, 'rb') as f:
                data = f.read()
        except OSError as e:
            print(f"  skip {fpath}: {e}")
            continue

        builder.add_file(gpath, st.st_mode & 0o777 | 0o100000, 0, 0,
                         len(data), int(st.st_mtime), data)
        file_count += 1
        if file_count % 500 == 0:
            print(f"  {file_count} files ...")

print(f"Added {dir_count} directories, {file_count} files")
print(f"Building {OUTPUT} ({SIZE_MB} MB) ...")
builder.build(OUTPUT)
print(f"Done: {OUTPUT} ({os.path.getsize(OUTPUT) // (1024*1024)} MB)")
