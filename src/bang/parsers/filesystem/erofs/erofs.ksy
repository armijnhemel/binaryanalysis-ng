meta:
  id: erofs
  title: Enhanced Read-Only File System
  license: Apache-2.0
  encoding: UTF-8
  endian: le
doc-ref: https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git
seq:
  - id: data
    size: 1024
  - id: superblock
    type: superblock
instances:
  root_inode:
    pos: inode_offset_base + 32 * superblock.header.root_nid
    type: inode
  inode_offset_base:
    value: superblock.header.meta_block_address * superblock.magic_header.block_size
types:
  superblock:
    seq:
      - id: magic_header
        type: magic_header
      - id: header
        type: header
        size: magic_header.len_superblock - magic_header._sizeof
  magic_header:
    seq:
      - id: magic
        contents: [0xe2, 0xe1, 0xf5, 0xe0]
      - id: crc32
        type: u4
      - id: feature_compat_flags
        type: u4
      - id: block_size_bits
        type: u1
      - id: ext_slots
        type: u1
        doc: superblock size = 128 + sb_extslots * 16
    instances:
      checksum:
        value: feature_compat_flags & 0x01 == 0x01
      mtime:
        value: feature_compat_flags & 0x02 == 0x02
      len_superblock:
        value: 128 + ext_slots * 16
      block_size:
        value: 1 << block_size_bits
  header:
    seq:
      - id: root_nid
        type: u2
      - id: inos
        type: u8
        doc: total valid ino # (== f_files - f_favail)
      - id: build_time
        type: u8
      - id: build_time_nsec
        type: u4
        doc: inode v1 time derivation in nano scale
      - id: num_blocks
        type: u4
        doc: used for statfs
      - id: meta_block_address
        type: u4
        doc: start block address of metadata area
      - id: xattr_block_address
        type: u4
        doc: start block address of shared xattr area
      - id: uuid
        size: 16
        doc: 128-bit uuid for volume
      - id: volume_name
        size: 16
      - id: feature_incompat_flags
        type: u4
      - id: available_compr_algs_or_lz4_max_distance
        type: u2
      - id: extra_devices
        type: u2
      - id: devt_slotoff
        type: u2
      - id: reserved_1
        size: 6
      - id: packed_nid
        type: u8
      - id: reserved_2
        size: 24
    instances:
      len_file:
        value: num_blocks * _parent.magic_header.block_size
      lz4_zero_padding:
        value: feature_incompat_flags & 0x01 == 0x01
      compr_cfgs:
        value: feature_incompat_flags & 0x02 == 0x02
      big_pcluster:
        value: feature_incompat_flags & 0x02 == 0x02
      chunked_file:
        value: feature_incompat_flags & 0x04 == 0x04
      device_table:
        value: feature_incompat_flags & 0x08 == 0x08
      ztail_packing:
        value: feature_incompat_flags & 0x10 == 0x10
      fragments:
        value: feature_incompat_flags & 0x20 == 0x20
      dedupe:
        value: feature_incompat_flags & 0x20 == 0x20
  inode:
    seq:
      - id: format
        type: u2
      - id: inode
        type: ondisk_inode(extended)
      #- id: xattrs
      #  type: xattr
      #  repeat: expr
      #  repeat-expr: inode.num_xattr
      - id: data
        size: len_inode
        type: directory_entries
    instances:
      extended:
        value: format & 0x01 == 0x01
      inode_layout:
        value: format >> 1
        enum: layouts
      len_inode:
        value: 'extended ? inode.inode_body.as<extended_inode>.len_inode : inode.inode_body.as<compact_inode>.len_inode'
    enums:
      layouts:
        0: plain
        1: compression_legacy
        2: inline
        3: compression
        4: chunk_based
  ondisk_inode:
    params:
      - id: is_extended
        type: bool
    seq:
      - id: num_xattr
        -orig-id: i_xattr_icount
        type: u2
        valid: 0
      - id: mode
        type: u2
      - id: inode_body
        type:
          switch-on: is_extended
          cases:
            false: compact_inode
            true: extended_inode
    instances:
      is_socket:
        value: mode & 0o0170000 == 0o140000
      is_link:
        value: mode & 0o0170000 == 0o120000
      is_regular:
        value: mode & 0o0170000 == 0o100000
      is_block_device:
        value: mode & 0o0170000 == 0o60000
      is_dir:
        value: mode & 0o0170000 == 0o40000
      is_character_device:
        value: mode & 0o0170000 == 0o20000
      is_fifo:
        value: mode & 0o0170000 == 0o10000
  compact_inode:
    # 32-byte reduced form of an ondisk inode
    seq:
      - id: nlink
        type: u2
      - id: len_inode
        type: u4
      - id: reserved_1
        type: u4
      - id: some_union
        type: u4
      - id: ino
        type: u4
      - id: uid
        type: u2
      - id: gid
        type: u2
      - id: reserved_2
        type: u4
  extended_inode:
    # 64-byte complete form of an ondisk inode
    seq:
      - id: reserved_1
        type: u2
      - id: len_inode
        type: u8
      - id: some_union
        type: u4
      - id: ino
        type: u4
      - id: uid
        type: u4
      - id: gid
        type: u4
      - id: ctime
        type: u8
      - id: ctime_nsec
        type: u4
      - id: nlink
        type: u4
      - id: reserved_2
        size: 16
  xattr_ibody_header:
    seq:
      - id: reserved_1
        size: 4
      - id: num_shared_count
        type: u1
      - id: reserved_2
        size: 7
      - id: shared_xattrs
        type: u4
        repeat: expr
        repeat-expr: num_shared_count
  directory_entries:
    seq:
      - id: entries
        type: directory_entry(_index)
        repeat: expr
        repeat-expr: num_entries
    instances:
      first_name_offset:
        pos: 8
        type: u2
      num_entries:
        value: first_name_offset / sizeof<directory_entry>
      names:
        type: name(_index)
        repeat: expr
        repeat-expr: num_entries
    types:
      name:
        params:
          - id: index
            type: u4
        instances:
          len_name:
            value: 'index == _parent.entries.size - 1 ? _parent._parent.len_inode - _parent.entries[index].ofs_name  : _parent.entries[index+1].ofs_name - _parent.entries[index].ofs_name'
          name:
            pos: _parent.entries[index].ofs_name
            size: len_name
            type: strz
  directory_entry:
    params:
      - id: index
        type: u4
    seq:
      - id: node_id
        type: u8
      - id: ofs_name
        -orig-id: nameoff
        type: u2
      - id: file_type
        type: u1
        enum: file_types
      - id: reserved
        type: u1
    instances:
      inode:
        io: _root._io
        pos: _root.inode_offset_base + 32 * node_id
        type: inode
enums:
  file_types:
    0: unknown
    1: regular_file
    2: directory
    3: character_device
    4: block_device
    5: fifo
    6: socket
    7: symlink
  compression:
    0: lz4
    1: lzma
