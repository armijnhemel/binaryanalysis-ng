meta:
  id: minix1l
  title: Minix file system (Linux extended variant)
  license: CC0-1.0
  endian: le
  encoding: ASCII
seq:
  - id: bootblock
    size: block_size
  - id: superblock
    type: superblock
    size: block_size
  - id: inodes_bitmap
    size: superblock.num_inode_bitmap_blocks * block_size
  - id: zones_bitmap
    size: superblock.num_zone_bitmap_blocks * block_size
  - id: inodes
    type: inode
    repeat: expr
    repeat-expr: superblock.num_inodes
  - id: padding
    size: (- _io.pos) % block_size
instances:
  block_size:
    value: 1024
  inode_size:
    value: 32
  zones:
    pos: superblock.first_data_zone * block_size
    type: zone
    repeat: expr
    repeat-expr: superblock.num_zones - superblock.first_data_zone
types:
  superblock:
    seq:
      - id: num_inodes
        type: u2
        valid:
          min: 1
      - id: num_zones
        type: u2
        valid:
          min: 1
      - id: num_inode_bitmap_blocks
        type: u2
        valid:
          max: _root._io.size / _root.block_size
      - id: num_zone_bitmap_blocks
        type: u2
        valid:
          max: _root._io.size / _root.block_size
      - id: first_data_zone
        type: u2
        valid:
          min: 2 + num_inode_bitmap_blocks + num_zone_bitmap_blocks + ((num_inodes/_root.inode_size) % _root.block_size)
          max: num_zones
      - id: size_log_zone
        type: u2
      - id: max_size
        type: u4
      - id: magic
        contents: [0x8f, 0x13]
      - id: state
        type: u2
  inode:
    seq:
      - id: mode
        type: u2
      - id: uid
        type: u2
      - id: size
        type: u4
      - id: time
        type: u4
      - id: gid
        type: u1
      - id: links
        type: u1
      - id: direct_zone_numbers
        type: zone_number
        repeat: expr
        repeat-expr: 7
      - id: indirect_zone_number
        type: indirect_zone_number
      - id: double_indirect_zone_number
        type: double_indirect_zone_number
  double_indirect_zone_number:
    seq:
      - id: number
        type: u2
        valid:
          max: _root.superblock.num_zones
    instances:
      zone_data:
        pos: number * _root.block_size
        io: _root._io
        type: indirect_zone_number
        repeat: expr
        repeat-expr: _root.block_size/number._sizeof
        if: number != 0
  indirect_zone_number:
    seq:
      - id: number
        type: u2
        valid:
          max: _root.superblock.num_zones
    instances:
      zone_data:
        pos: number * _root.block_size
        io: _root._io
        type: zone_number
        repeat: expr
        repeat-expr: _root.block_size/number._sizeof
        if: number != 0
  zone_number:
    seq:
      - id: number
        type: u2
        valid:
          max: _root.superblock.num_zones
    instances:
      zone_data:
        pos: number * _root.block_size
        type: zone
        io: _root._io
        if: number != 0
  zone:
    seq:
      - id: data
        size: _root.block_size
