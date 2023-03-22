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
    pos: superblock.header.meta_block_address * superblock.magic_header.block_size + 32 * superblock.header.root_nid
    type: inode
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
      - id: blocks
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
        type:
          switch-on: extended
          cases:
            false: compact_inode
            true: extended_inode
      #- id: xattrs
      #  type: xattr
      #  repeat: expr
      #  repeat-expr: inode.num_xattr
      - id: data
        size: len_inode
    instances:
      extended:
        value: format & 0x01 == 0x01
      inode_layout:
        value: format >> 1
        enum: layouts
      len_inode:
        value: 'extended ? inode.as<extended_inode>.len_inode : inode.as<compact_inode>.len_inode'
    enums:
      layouts:
        0: plain
        1: compression_legacy
        2: inline
        3: compression
        4: chunk_based
  compact_inode:
    # 32-byte reduced form of an ondisk inode
    seq:
      - id: num_xattr
        -orig-id: i_xattr_icount
        type: u2
        valid: 0
      - id: mode
        type: u2
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
  extended_inode:
    # 64-byte complete form of an ondisk inode
    seq:
      - id: num_xattr
        -orig-id: i_xattr_icount
        type: u2
        valid: 0
      - id: mode
        type: u2
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
  directory:
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
