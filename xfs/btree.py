"""XFS B+tree traversal and modification engine.

Supports both short-form (alloc, inobt — 16-byte header, 4-byte AG pointers)
and long-form (bmap — 24-byte header, 8-byte fsblock pointers).

BTreeCursor is the one class in pyirix/xfs — justified because B+tree
traversal is inherently stateful (current position, path through tree).
"""

import struct

from pyirix.xfs.constants import (
    XFS_BTREE_SBLOCK_SIZE, XFS_BTREE_LBLOCK_SIZE,
    NULLFSBLOCK, NULLAGBLOCK,
    XFSCorruptionError, XFSNoSpaceError,
)
from pyirix.xfs.ondisk import (
    parse_btree_sblock, pack_btree_sblock,
    parse_btree_lblock, pack_btree_lblock,
    fsblock_to_offset, valid_fsblock, valid_agblock,
)


class BTreeCursor:
    """Cursor for traversing and modifying XFS B+trees.

    Two modes:
    - Short-form (alloc/inobt): 16-byte header, 4-byte AG-relative block pointers
    - Long-form (bmap): 24-byte header, 8-byte fsblock pointers

    Parameters:
        f: open file object
        part_offset: byte offset of XFS partition start
        sb: superblock dict
        root_block: root block number (agblock for short, fsblock for long)
        agno: AG number (required for short-form, ignored for long-form)
        magic: expected block magic number
        key_size: size of each key in bytes
        rec_size: size of each leaf record in bytes
        long_form: True for bmap (8-byte ptrs), False for alloc/inobt (4-byte ptrs)
    """

    def __init__(self, f, part_offset, sb, root_block, agno, magic,
                 key_size, rec_size, long_form=False):
        self.f = f
        self.part_offset = part_offset
        self.sb = sb
        self.root_block = root_block
        self.agno = agno
        self.magic = magic
        self.key_size = key_size
        self.rec_size = rec_size
        self.long_form = long_form

        self.blocksize = sb['sb_blocksize']
        self.hdr_size = XFS_BTREE_LBLOCK_SIZE if long_form else XFS_BTREE_SBLOCK_SIZE
        self.ptr_size = 8 if long_form else 4

        # Calculate max records/keys per block
        self.leaf_maxrecs = (self.blocksize - self.hdr_size) // rec_size
        self.node_maxrecs = (self.blocksize - self.hdr_size) // (key_size + self.ptr_size)

        # Current position: list of (block_data, block_num, index) from root to leaf
        self._path = []
        self._loaded = False

    def _read_block(self, block_num):
        """Read a B+tree block from disk."""
        offset = self._block_to_offset(block_num)
        self.f.seek(offset)
        data = self.f.read(self.blocksize)
        if len(data) < self.hdr_size:
            raise XFSCorruptionError(f"Short read on btree block {block_num}")
        return bytearray(data)

    def _write_block(self, block_num, data):
        """Write a B+tree block to disk."""
        offset = self._block_to_offset(block_num)
        self.f.seek(offset)
        self.f.write(bytes(data))

    def _block_to_offset(self, block_num):
        """Convert block number to disk byte offset."""
        if self.long_form:
            return fsblock_to_offset(self.sb, self.part_offset, block_num)
        else:
            # Short-form: block_num is AG-relative
            agblocks = self.sb['sb_agblocks']
            blocksize = self.sb['sb_blocksize']
            phys_block = self.agno * agblocks + block_num
            return self.part_offset + phys_block * blocksize

    def _parse_header(self, data):
        """Parse block header."""
        if self.long_form:
            return parse_btree_lblock(data)
        else:
            return parse_btree_sblock(data)

    def _pack_header(self, hdr):
        """Pack block header to bytes."""
        if self.long_form:
            return pack_btree_lblock(hdr)
        else:
            return pack_btree_sblock(hdr)

    def _null_ptr(self):
        """Return the null pointer value for this tree type."""
        return NULLFSBLOCK if self.long_form else NULLAGBLOCK

    def _valid_ptr(self, ptr):
        """Check if a pointer value is valid."""
        if self.long_form:
            return valid_fsblock(ptr)
        else:
            return valid_agblock(ptr)

    def _get_key(self, data, index):
        """Get key at 1-based index from an internal node."""
        off = self.hdr_size + (index - 1) * self.key_size
        return data[off:off + self.key_size]

    def _get_ptr(self, data, hdr, index):
        """Get pointer at 1-based index from an internal node."""
        # Pointers start after max_keys * key_size
        ptr_off = self.hdr_size + self.node_maxrecs * self.key_size + (index - 1) * self.ptr_size
        if self.long_form:
            return struct.unpack('>Q', data[ptr_off:ptr_off + 8])[0]
        else:
            return struct.unpack('>I', data[ptr_off:ptr_off + 4])[0]

    def _set_key(self, data, index, key_data):
        """Set key at 1-based index in an internal node."""
        off = self.hdr_size + (index - 1) * self.key_size
        data[off:off + self.key_size] = key_data

    def _set_ptr(self, data, index, ptr):
        """Set pointer at 1-based index in an internal node."""
        ptr_off = self.hdr_size + self.node_maxrecs * self.key_size + (index - 1) * self.ptr_size
        if self.long_form:
            struct.pack_into('>Q', data, ptr_off, ptr)
        else:
            struct.pack_into('>I', data, ptr_off, ptr)

    def _get_rec(self, data, index):
        """Get record at 1-based index from a leaf node."""
        off = self.hdr_size + (index - 1) * self.rec_size
        return data[off:off + self.rec_size]

    def _set_rec(self, data, index, rec_data):
        """Set record at 1-based index in a leaf node."""
        off = self.hdr_size + (index - 1) * self.rec_size
        data[off:off + self.rec_size] = rec_data

    def _extract_key_from_rec(self, rec_data):
        """Extract the key portion from a record (first key_size bytes)."""
        return rec_data[:self.key_size]

    def _compare_keys(self, key1, key2):
        """Compare two keys. Returns <0, 0, or >0.

        Default comparison: unsigned big-endian integer comparison.
        Works correctly for alloc (startblock), inobt (startino), and bmap (startoff).
        """
        # Compare key bytes as unsigned big-endian integers
        if len(key1) == 4:
            v1 = struct.unpack('>I', key1)[0]
            v2 = struct.unpack('>I', key2)[0]
        elif len(key1) == 8:
            v1 = struct.unpack('>Q', key1)[0]
            v2 = struct.unpack('>Q', key2)[0]
        else:
            # Byte-by-byte comparison
            v1, v2 = key1, key2

        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        return 0

    # ── Traversal ───────────────────────────────────────────────────

    def lookup_le(self, key):
        """Position cursor at largest record with key <= given key.

        Returns True if a valid record was found.
        """
        if isinstance(key, int):
            if self.key_size == 4:
                key = struct.pack('>I', key)
            else:
                key = struct.pack('>Q', key)

        self._path = []
        data = self._read_block(self.root_block)
        hdr = self._parse_header(data)

        if hdr is None or hdr['bb_magic'] != self.magic:
            return False

        block_num = self.root_block

        # Walk down from root to leaf
        while hdr['bb_level'] > 0:
            numrecs = hdr['bb_numrecs']
            if numrecs == 0:
                return False

            # Binary search for largest key <= target
            idx = self._bisect_node(data, numrecs, key)
            if idx < 1:
                idx = 1

            self._path.append((data, block_num, idx))

            ptr = self._get_ptr(data, hdr, idx)
            if not self._valid_ptr(ptr):
                return False

            data = self._read_block(ptr)
            hdr = self._parse_header(data)
            block_num = ptr

            if hdr is None or hdr['bb_magic'] != self.magic:
                return False

        # At leaf level — binary search for record
        numrecs = hdr['bb_numrecs']
        if numrecs == 0:
            self._path.append((data, block_num, 0))
            return False

        idx = self._bisect_leaf(data, numrecs, key)
        if idx < 1:
            # Key is smaller than all records — try previous block
            if self._valid_ptr(hdr['bb_leftsib']):
                # Move to previous leaf
                prev = hdr['bb_leftsib']
                data = self._read_block(prev)
                hdr = self._parse_header(data)
                block_num = prev
                idx = hdr['bb_numrecs']
            else:
                self._path.append((data, block_num, 0))
                return False

        self._path.append((data, block_num, idx))
        return True

    def lookup_ge(self, key):
        """Position cursor at smallest record with key >= given key.

        Returns True if a valid record was found.
        """
        if isinstance(key, int):
            if self.key_size == 4:
                key = struct.pack('>I', key)
            else:
                key = struct.pack('>Q', key)

        self._path = []
        data = self._read_block(self.root_block)
        hdr = self._parse_header(data)

        if hdr is None or hdr['bb_magic'] != self.magic:
            return False

        block_num = self.root_block

        while hdr['bb_level'] > 0:
            numrecs = hdr['bb_numrecs']
            if numrecs == 0:
                return False

            idx = self._bisect_node_ge(data, numrecs, key)
            if idx > numrecs:
                idx = numrecs

            self._path.append((data, block_num, idx))

            ptr = self._get_ptr(data, hdr, idx)
            if not self._valid_ptr(ptr):
                return False

            data = self._read_block(ptr)
            hdr = self._parse_header(data)
            block_num = ptr

            if hdr is None or hdr['bb_magic'] != self.magic:
                return False

        numrecs = hdr['bb_numrecs']
        if numrecs == 0:
            self._path.append((data, block_num, 0))
            return False

        idx = self._bisect_leaf_ge(data, numrecs, key)
        if idx > numrecs:
            # Try next leaf
            if self._valid_ptr(hdr['bb_rightsib']):
                nxt = hdr['bb_rightsib']
                data = self._read_block(nxt)
                hdr = self._parse_header(data)
                block_num = nxt
                idx = 1 if hdr['bb_numrecs'] > 0 else 0
            else:
                self._path.append((data, block_num, numrecs + 1))
                return False

        self._path.append((data, block_num, idx))
        return True

    def lookup_eq(self, key):
        """Position cursor at exact key match. Returns True if found."""
        if not self.lookup_le(key):
            return False
        rec = self.get_rec()
        if rec is None:
            return False
        rec_key = self._extract_key_from_rec(rec)
        return self._compare_keys(rec_key, key if isinstance(key, bytes) else
                                  (struct.pack('>I', key) if self.key_size == 4
                                   else struct.pack('>Q', key))) == 0

    def get_rec(self):
        """Get the record at current cursor position. Returns bytes or None."""
        if not self._path:
            return None
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        if idx < 1 or idx > hdr['bb_numrecs']:
            return None
        return bytes(self._get_rec(data, idx))

    def update_rec(self, rec_data):
        """Update the record at current cursor position."""
        if not self._path:
            raise XFSCorruptionError("No cursor position")
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        if idx < 1 or idx > hdr['bb_numrecs']:
            raise XFSCorruptionError("Invalid cursor position")
        self._set_rec(data, idx, rec_data)
        self._write_block(block_num, data)
        self._path[-1] = (data, block_num, idx)

    def increment(self):
        """Move cursor to next record. Returns True if valid."""
        if not self._path:
            return False
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        idx += 1

        if idx <= hdr['bb_numrecs']:
            self._path[-1] = (data, block_num, idx)
            return True

        # Move to right sibling
        rightsib = hdr['bb_rightsib']
        if not self._valid_ptr(rightsib):
            return False

        data = self._read_block(rightsib)
        hdr = self._parse_header(data)
        if hdr is None or hdr['bb_magic'] != self.magic:
            return False
        if hdr['bb_numrecs'] == 0:
            return False

        self._path[-1] = (data, rightsib, 1)
        return True

    def decrement(self):
        """Move cursor to previous record. Returns True if valid."""
        if not self._path:
            return False
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        idx -= 1

        if idx >= 1:
            self._path[-1] = (data, block_num, idx)
            return True

        # Move to left sibling
        leftsib = hdr['bb_leftsib']
        if not self._valid_ptr(leftsib):
            return False

        data = self._read_block(leftsib)
        hdr = self._parse_header(data)
        if hdr is None or hdr['bb_magic'] != self.magic:
            return False
        if hdr['bb_numrecs'] == 0:
            return False

        self._path[-1] = (data, leftsib, hdr['bb_numrecs'])
        return True

    # ── Modification ────────────────────────────────────────────────

    def insert_rec(self, rec_data, alloc_fn=None):
        """Insert a record into the B+tree.

        The cursor should be positioned at the insertion point (via lookup_ge).
        alloc_fn(agno) -> agblock: allocator for new blocks on split.

        Returns True on success.
        """
        if not self._path:
            raise XFSCorruptionError("No cursor position for insert")

        key = self._extract_key_from_rec(rec_data)
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        numrecs = hdr['bb_numrecs']

        if numrecs < self.leaf_maxrecs:
            # Room in this leaf — insert at position
            self._leaf_insert(data, hdr, idx, rec_data)
            hdr['bb_numrecs'] = numrecs + 1
            self._write_header(data, hdr)
            self._write_block(block_num, data)
            self._path[-1] = (data, block_num, idx)

            # Update parent key if we inserted at position 1
            if idx == 1 and len(self._path) > 1:
                self._update_parent_key(key)

            return True

        # Need to split — requires block allocator
        if alloc_fn is None:
            raise XFSNoSpaceError("Leaf full and no allocator provided")

        return self._split_and_insert(rec_data, alloc_fn)

    def delete_rec(self):
        """Delete the record at current cursor position.

        Returns True on success. Does NOT handle block merging (leaves
        underflowing blocks in place — acceptable for our use case).
        """
        if not self._path:
            raise XFSCorruptionError("No cursor position for delete")

        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        numrecs = hdr['bb_numrecs']

        if idx < 1 or idx > numrecs:
            raise XFSCorruptionError("Invalid cursor position for delete")

        # Shift records left
        for i in range(idx, numrecs):
            src = self._get_rec(data, i + 1)
            self._set_rec(data, i, src)

        # Zero the last record
        off = self.hdr_size + (numrecs - 1) * self.rec_size
        data[off:off + self.rec_size] = b'\x00' * self.rec_size

        hdr['bb_numrecs'] = numrecs - 1
        self._write_header(data, hdr)
        self._write_block(block_num, data)

        # Update parent key if we deleted at position 1 and records remain
        if idx == 1 and numrecs > 1 and len(self._path) > 1:
            new_first_rec = self._get_rec(data, 1)
            new_key = self._extract_key_from_rec(new_first_rec)
            self._update_parent_key(new_key)

        self._path[-1] = (data, block_num, min(idx, hdr['bb_numrecs']))
        return True

    # ── Walk all records ────────────────────────────────────────────

    def walk_all(self):
        """Walk all leaf records in order. Yields record bytes.

        Starts from leftmost leaf, follows right sibling chain.
        """
        # Find leftmost leaf
        data = self._read_block(self.root_block)
        hdr = self._parse_header(data)
        if hdr is None or hdr['bb_magic'] != self.magic:
            return

        block_num = self.root_block

        while hdr['bb_level'] > 0:
            if hdr['bb_numrecs'] == 0:
                return
            ptr = self._get_ptr(data, hdr, 1)
            if not self._valid_ptr(ptr):
                return
            data = self._read_block(ptr)
            hdr = self._parse_header(data)
            block_num = ptr
            if hdr is None or hdr['bb_magic'] != self.magic:
                return

        # Walk leaf chain
        visited = set()
        while self._valid_ptr(block_num) and block_num not in visited:
            visited.add(block_num)
            for i in range(1, hdr['bb_numrecs'] + 1):
                yield bytes(self._get_rec(data, i))

            rightsib = hdr['bb_rightsib']
            if not self._valid_ptr(rightsib):
                break
            block_num = rightsib
            data = self._read_block(block_num)
            hdr = self._parse_header(data)
            if hdr is None or hdr['bb_magic'] != self.magic:
                break

    # ── Private helpers ─────────────────────────────────────────────

    def _bisect_node(self, data, numrecs, key):
        """Binary search in internal node. Returns index of largest key <= target."""
        lo, hi = 1, numrecs
        result = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            mid_key = self._get_key(data, mid)
            cmp = self._compare_keys(mid_key, key)
            if cmp <= 0:
                result = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    def _bisect_node_ge(self, data, numrecs, key):
        """Binary search in internal node for >= lookup."""
        lo, hi = 1, numrecs
        result = numrecs
        while lo <= hi:
            mid = (lo + hi) // 2
            mid_key = self._get_key(data, mid)
            cmp = self._compare_keys(mid_key, key)
            if cmp >= 0:
                result = mid
                hi = mid - 1
            else:
                lo = mid + 1
        return result

    def _bisect_leaf(self, data, numrecs, key):
        """Binary search in leaf. Returns index of largest record key <= target."""
        lo, hi = 1, numrecs
        result = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            rec = self._get_rec(data, mid)
            rec_key = self._extract_key_from_rec(rec)
            cmp = self._compare_keys(rec_key, key)
            if cmp <= 0:
                result = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    def _bisect_leaf_ge(self, data, numrecs, key):
        """Binary search in leaf for >= lookup. Returns smallest index with key >= target."""
        lo, hi = 1, numrecs
        result = numrecs + 1
        while lo <= hi:
            mid = (lo + hi) // 2
            rec = self._get_rec(data, mid)
            rec_key = self._extract_key_from_rec(rec)
            cmp = self._compare_keys(rec_key, key)
            if cmp >= 0:
                result = mid
                hi = mid - 1
            else:
                lo = mid + 1
        return result

    def _leaf_insert(self, data, hdr, idx, rec_data):
        """Insert record at idx, shifting existing records right."""
        numrecs = hdr['bb_numrecs']
        # idx is where we want to insert (1-based)
        # If idx is 0 or beyond numrecs, insert at end
        if idx < 1:
            idx = 1
        if idx > numrecs + 1:
            idx = numrecs + 1

        # Shift records from idx..numrecs right by one
        for i in range(numrecs, idx - 1, -1):
            src = self._get_rec(data, i)
            self._set_rec(data, i + 1, src)

        self._set_rec(data, idx, rec_data)

    def _write_header(self, data, hdr):
        """Write header back into block data."""
        hdr_bytes = self._pack_header(hdr)
        data[:len(hdr_bytes)] = hdr_bytes

    def _update_parent_key(self, new_key):
        """Update the key in the parent node that points to our current block."""
        if len(self._path) < 2:
            return
        # Walk up the path updating keys
        for level in range(len(self._path) - 2, -1, -1):
            parent_data, parent_block, parent_idx = self._path[level]
            if parent_idx >= 1:
                self._set_key(parent_data, parent_idx, new_key)
                self._write_block(parent_block, parent_data)
                self._path[level] = (parent_data, parent_block, parent_idx)
                break

    def _split_and_insert(self, rec_data, alloc_fn):
        """Split a full leaf and insert the record.

        Allocates a new block, moves half the records to it,
        and inserts a key/pointer in the parent (splitting recursively if needed).
        """
        data, block_num, idx = self._path[-1]
        hdr = self._parse_header(data)
        numrecs = hdr['bb_numrecs']

        # Allocate new block
        new_block_num = alloc_fn(self.agno)

        # Split point
        split = numrecs // 2 + 1  # records 1..split-1 stay, split..numrecs move

        # Create new block
        new_data = bytearray(self.blocksize)
        new_hdr = {
            'bb_magic': self.magic,
            'bb_level': 0,
            'bb_numrecs': numrecs - split + 1,
            'bb_leftsib': block_num,
            'bb_rightsib': hdr['bb_rightsib'],
        }
        self._write_header(new_data, new_hdr)

        # Copy records split..numrecs to new block
        for i in range(split, numrecs + 1):
            rec = self._get_rec(data, i)
            self._set_rec(new_data, i - split + 1, rec)

        # Update old block
        hdr['bb_numrecs'] = split - 1
        hdr['bb_rightsib'] = new_block_num
        self._write_header(data, hdr)

        # Zero moved records in old block
        for i in range(split, numrecs + 1):
            off = self.hdr_size + (i - 1) * self.rec_size
            data[off:off + self.rec_size] = b'\x00' * self.rec_size

        # Update right neighbor's leftsib
        if self._valid_ptr(new_hdr['bb_rightsib']):
            right_data = self._read_block(new_hdr['bb_rightsib'])
            right_hdr = self._parse_header(right_data)
            right_hdr['bb_leftsib'] = new_block_num
            self._write_header(right_data, right_hdr)
            self._write_block(new_hdr['bb_rightsib'], right_data)

        # Insert the new record into the appropriate block
        key = self._extract_key_from_rec(rec_data)
        if idx < split:
            # Insert in old block
            self._leaf_insert(data, hdr, idx, rec_data)
            hdr['bb_numrecs'] += 1
            self._write_header(data, hdr)
        else:
            # Insert in new block
            new_idx = idx - split + 1
            new_hdr_parsed = self._parse_header(new_data)
            self._leaf_insert(new_data, new_hdr_parsed, new_idx, rec_data)
            new_hdr_parsed['bb_numrecs'] += 1
            self._write_header(new_data, new_hdr_parsed)

        # Write both blocks
        self._write_block(block_num, data)
        self._write_block(new_block_num, new_data)

        # Insert key/pointer for new block in parent
        new_block_first_rec = self._get_rec(new_data, 1)
        new_key = self._extract_key_from_rec(new_block_first_rec)

        if len(self._path) <= 1:
            # Root was a leaf — need to create new root
            self._create_new_root(block_num, data, new_block_num, new_data, alloc_fn)
        else:
            self._insert_in_parent(new_key, new_block_num, alloc_fn)

        return True

    def _insert_in_parent(self, key, new_child, alloc_fn):
        """Insert a key/pointer pair in the parent node."""
        if len(self._path) < 2:
            return

        parent_data, parent_block, parent_idx = self._path[-2]
        parent_hdr = self._parse_header(parent_data)
        numrecs = parent_hdr['bb_numrecs']

        if numrecs < self.node_maxrecs:
            # Room in parent
            insert_at = parent_idx + 1

            # Shift keys and pointers right
            for i in range(numrecs, insert_at - 1, -1):
                src_key = self._get_key(parent_data, i)
                self._set_key(parent_data, i + 1, src_key)
                src_ptr = self._get_ptr(parent_data, parent_hdr, i)
                self._set_ptr(parent_data, i + 1, src_ptr)

            self._set_key(parent_data, insert_at, key)
            self._set_ptr(parent_data, insert_at, new_child)

            parent_hdr['bb_numrecs'] = numrecs + 1
            self._write_header(parent_data, parent_hdr)
            self._write_block(parent_block, parent_data)
            self._path[-2] = (parent_data, parent_block, parent_idx)
        else:
            # Parent is full — would need to split parent too
            # For our use cases (IRIX disk images), this is very rare
            raise XFSNoSpaceError("Parent node full — recursive split not yet implemented")

    def _create_new_root(self, left_block, left_data, right_block, right_data, alloc_fn):
        """Create a new root node when the old root (a leaf) was split."""
        new_root_num = alloc_fn(self.agno)

        root_data = bytearray(self.blocksize)
        root_hdr = {
            'bb_magic': self.magic,
            'bb_level': 1,
            'bb_numrecs': 2,
            'bb_leftsib': self._null_ptr(),
            'bb_rightsib': self._null_ptr(),
        }
        self._write_header(root_data, root_hdr)

        # Key 1 = first key of left block
        left_first = self._get_rec(left_data, 1)
        self._set_key(root_data, 1, self._extract_key_from_rec(left_first))
        self._set_ptr(root_data, 1, left_block)

        # Key 2 = first key of right block
        right_first = self._get_rec(right_data, 1)
        self._set_key(root_data, 2, self._extract_key_from_rec(right_first))
        self._set_ptr(root_data, 2, right_block)

        self._write_block(new_root_num, root_data)
        self.root_block = new_root_num


# ── Convenience Functions ───────────────────────────────────────────

def walk_bmap_btree(f, part_offset, sb, fork_data):
    """Walk a bmap B+tree and return all extents.

    This is a standalone function for reading extent trees without
    the full cursor machinery. Migrated from sgi_fs.py.
    """
    from pyirix.xfs.inode import _btree_get_extents
    return _btree_get_extents(f, part_offset, sb, fork_data)
