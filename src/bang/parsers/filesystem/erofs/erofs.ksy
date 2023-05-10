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
    pos: ofs_metadata_area + (32 * superblock.header.root_nid)
    type: inode
  ofs_metadata_area:
    value: superblock.header.meta_block_address * superblock.magic_header.block_size
  ofs_shared_xattr_area:
    value: superblock.header.xattr_block_address * superblock.magic_header.block_size
  blocks:
    pos: 0
    size: superblock.magic_header.block_size
    repeat: expr
    repeat-expr: superblock.header.num_blocks
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
        type: strz
      - id: feature_incompat_flags
        type: u4
      - id: compression_information
        size: 2
        type: compression_information
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
    types:
      compression_information:
        seq:
          - id: raw
            size: 2
        instances:
          available_compression_algorithms:
            pos: 0
            type: u2
          lz4_max_distance:
            pos: 0
            type: u2
  inode:
    seq:
      - id: format
        type: u2
      - id: inode
        type: ondisk_inode(extended)
      - id: xattrs
        type: xattrs(inode.num_inline_xattr)
        if: inode.num_inline_xattr != 0
      - id: data
        type:
          switch-on: inode_layout
          cases:
            #layouts::plain: plain
            layouts::inline: inline
            #layouts::compression: compression
    instances:
      extended:
        value: format & 0x01 == 0x01
      inode_layout:
        value: format >> 1
        enum: layouts
      len_inode:
        value: 'extended ? inode.body.as<extended_inode>.len_inode : inode.body.as<compact_inode>.len_inode'
    types:
      compression:
        seq:
          - id: map_header
            type: map_header
      #plain:
      #  instances:
      #    node_data:
      #      io: _root._io
      #      pos: raw_block_address * _root.superblock.magic_header.block_size
      #      size: '(_parent.len_inode / _root.superblock.magic_header.block_size) * _root.superblock.magic_header.block_size'
      #      if: _parent.inode.is_regular
      #    raw_block_address:
      #      value: '_parent.extended ? _parent.inode.body.as<extended_inode>.specific.raw_block_address : _parent.inode.body.as<compact_inode>.specific.raw_block_address'
      inline:
        # for the inline data: the metadata for every format except
        # regular files is kept inline. For regular files, if the
        # data is larger than the block size as defined in the superblock
        # it can be found at the address found in the node specific
        # information found in the inode information, except for the
        # last bit of data if it cannot fill a full block.
        seq:
          - id: dir_entries
            size: _parent.len_inode
            type: directory_entries
            if: _parent.inode.is_dir
          - id: link_data
            size: _parent.len_inode
            type: strz
            if: _parent.inode.is_link
          - id: last_inline_data
            size: _parent.len_inode % _root.superblock.magic_header.block_size
            if: _parent.inode.is_regular
        instances:
          node_data:
            io: _root._io
            pos: raw_block_address * _root.superblock.magic_header.block_size
            size: '(_parent.len_inode / _root.superblock.magic_header.block_size) * _root.superblock.magic_header.block_size'
            if: _parent.inode.is_regular
          raw_block_address:
            value: '_parent.extended ? _parent.inode.body.as<extended_inode>.specific.raw_block_address : _parent.inode.body.as<compact_inode>.specific.raw_block_address'
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
      - id: num_inline_xattr
        -orig-id: i_xattr_icount
        type: u2
      - id: mode
        type: u2
      - id: body
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
      - id: specific
        size: 4
        type: node_specific_union
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
      - id: specific
        size: 4
        type: node_specific_union
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
  node_specific_union:
    seq:
      - id: raw
        size: 4
    instances:
      compressed_blocks:
        # file total compressed blocks for data mapping 1
        pos: 0
        type: u4
      raw_block_address:
        # for raw blocks, example: regular files under data mapping 2
        pos: 0
        type: u4
      rdev:
        # device files
        pos: 0
        type: u4
      chunk_info:
        # information specifif for the chunked data layout
        pos: 0
        type: chunk_info
  xattrs:
    # the xattr space consists of a header, an array of ids for
    # shared xattr, which are offsets to xattrs somewhere else in
    # the file. The rest of the data is used for inline xattrs.
    params:
      - id: num_inline_xattr
        type: u4
    seq:
      - id: header
        type: xattr_ibody_header
      - id: shared_xattrs_ids
        type: shared_xattr_id
        repeat: expr
        repeat-expr: header.num_shared_count
      - id: inline_xattr
        size: (num_inline_xattr - 1 - header.num_shared_count) * 4
        type: inline_xattrs
    types:
      shared_xattr_id:
        seq:
          - id: xattr_id
            type: u4
        instances:
          xattr:
            io: _root._io
            pos: _root.ofs_shared_xattr_area + (4 * xattr_id)
            type: xattr_entry
      inline_xattrs:
        seq:
          - id: entry
            type: xattr_entry
            repeat: eos
  xattr_ibody_header:
    seq:
      - id: reserved_1
        size: 4
      - id: num_shared_count
        type: u1
      - id: reserved_2
        size: 7
  xattr_entry:
    seq:
      - id: len_name
        type: u1
      - id: name_index
        type: u1
        enum: xattr_name_index
      - id: len_value
        type: u2
      - id: name
        size: len_name
        type: str
      - id: value
        size: len_value
      - id: padding
        size: -(len_value + len_name) % 4
  chunk_info:
    seq:
      - id: format
        type: u2
      - id: reserved
        size: 2
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
            value: 'index == _parent.entries.size - 1 ? _parent._parent._parent.len_inode - _parent.entries[index].ofs_name  : _parent.entries[index+1].ofs_name - _parent.entries[index].ofs_name'
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
        valid:
          any-of:
            - file_types::regular_file
            - file_types::directory
            - file_types::character_device
            - file_types::block_device
            - file_types::fifo
            - file_types::socket
            - file_types::symlink
      - id: reserved
        type: u1
    instances:
      inode:
        io: _root._io
        pos: _root.ofs_metadata_area + (32 * node_id)
        type: inode
      name:
        value: _parent.names[index]

  map_header:
    seq:
      - id: offset_or_encoded_size
        size: 4
        type: map_header_union
      - id: advise
        type: u2
      - id: algorithm_type
        type: u1
      - id: cluster_bits
        type: u1
    instances:
      compacted_2b:
        value: advise & 0x1 == 0x1
      big_pcluster_1:
        value: advise & 0x2 == 0x2
      big_pcluster_2:
        value: advise & 0x4 == 0x4
      inline_pcluster:
        value: advise & 0x8 == 0x8
      interlaced_pcluster:
        value: advise & 0x10 == 0x10
      interlaced_fragment_pcluster:
        value: advise & 0x20 == 0x20
      algorithm_type_head_1:
        value: algorithm_type & 0xf
        enum: compression
      algorithm_type_head_2:
        value: algorithm_type >> 4
        enum: compression
      whole_file_packed:
        value: cluster_bits >> 7
      logical_cluster_bits:
        value: (cluster_bits & 0x7) + 12
      logical_cluster_size:
        value: 1 << logical_cluster_bits
    types:
      map_header_union:
        seq:
          - id: raw
            size: 4
        instances:
          ofs_fragment:
            pos: 0
            type: u4
          len_encoded_tailpacking_data:
            pos: 2
            type: u2
  lz4_configs:
    seq:
      - id: max_distance
        type: u2
      - id: max_pcluster_blocks
        type: u2
      - id: reserved
        size: 10
  lzma_configs:
    seq:
      - id: dict_size
        type: u4
      - id: format
        type: u2
      - id: reserved
        size: 8
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
  xattr_name_index:
    1: user
    2: posix_acl_access
    3: posix_acl_default
    4: trusted
    5: lustre
    6: security
