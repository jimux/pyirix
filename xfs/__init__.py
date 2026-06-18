"""XFS filesystem read/write/create for SGI disk images.

Supports IRIX V1 and V4 XFS filesystems: read, write, create from scratch
(mkfs), and diagnose/repair. Provides both a library API and a CLI
(python3 -m pyirix.xfs).
"""

# Image layer
from pyirix.xfs.image import (
    open_disk_image,
    read_vh,
    find_partition,
    find_xfs_partition,
    detect_filesystem,
    is_qcow2,
)

# Superblock
from pyirix.xfs.superblock import (
    read_superblock,
    write_superblock,
    sash_compatible,
    zero_log,
)

# Inode
from pyirix.xfs.inode import (
    read_inode,
    write_inode,
    init_inode,
    get_extents,
    set_extents,
    read_file_data,
    write_file_data,
    read_symlink,
)

# Directory
from pyirix.xfs.directory import (
    read_dir_entries,
    read_dir_sf,
    read_dir_sf_parent,
    add_entry_sf,
    remove_entry_sf,
    init_dir_sf,
    add_entry_v1_leaf,
    remove_entry_v1_leaf,
    add_entry_dir2_block,
    remove_entry_dir2_block,
    sf_to_v1_leaf,
    sf_to_dir2_block,
)

# On-disk structures
from pyirix.xfs.ondisk import (
    parse_superblock,
    pack_superblock,
    parse_agf,
    pack_agf,
    parse_agi,
    pack_agi,
    parse_inode_core,
    pack_inode_core,
    parse_bmbt_rec,
    pack_bmbt_rec,
    parse_alloc_rec,
    pack_alloc_rec,
    parse_inobt_rec,
    pack_inobt_rec_full,
    parse_btree_sblock,
    pack_btree_sblock,
    parse_btree_lblock,
    pack_btree_lblock,
    xfs_da_hashname,
    ino_to_offset,
    fsblock_to_offset,
    agbno_to_fsblock,
    fsblock_to_agno,
    fsblock_to_agbno,
    agino_to_ino,
    valid_fsblock,
    valid_agblock,
    has_dirv2,
    has_ftype,
)

# B+tree
from pyirix.xfs.btree import BTreeCursor

# Allocation
from pyirix.xfs.alloc import (
    read_agf,
    write_agf,
    alloc_block,
    free_block,
    alloc_blocks_for_file,
)

# Inode allocation
from pyirix.xfs.ialloc import (
    read_agi,
    write_agi,
    alloc_inode,
    free_inode,
)

# High-level operations
from pyirix.xfs.operations import (
    resolve_path,
    list_dir,
    list_recursive,
    extract_recursive,
    create_file,
    write_file,
    delete_file,
    create_symlink,
    mknod,
    read_dev,
    mkdir,
    rmdir,
    chmod,
    chown,
)

# Exceptions
from pyirix.xfs.constants import (
    XFSError,
    XFSCorruptionError,
    XFSNoSpaceError,
    XFSPathError,
    XFSExistsError,
    XFSNotEmptyError,
)

# Create (mkfs) — build an IRIX V1-directory XFS from scratch
from pyirix.xfs.mkfs import mkfs_xfs, make_xfs_image

# Diagnose / repair
from pyirix.xfs.repair import (
    check_xfs,
    repair_xfs,
    repair_version_bits,
    recover_superblock,
    clean_log,
    find_secondary_superblock,
    CheckReport,
    Finding,
)
