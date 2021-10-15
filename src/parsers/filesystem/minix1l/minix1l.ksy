meta:
  id: minix1l
  title: Minix file system (Linux extended variant
  license: CC0-1.0
  endian: le
  encoding: ASCII
seq:
  - id: bootblock
    size: 1024
  - id: superblock
    type: superblock
    size: 1024
  - id: inodes_bitmap
    size: superblock.num_inode_bitmap_blocks * 1024
  - id: zones_bitmap
    size: superblock.num_zone_bitmap_blocks * 1024
  - id: inodes
    type: inode
    repeat: expr
    repeat-expr: superblock.num_inodes
types:
  superblock:
    seq:
      - id: num_inodes
        type: u2
        valid:
          expr: num_inodes > 0
      - id: num_zones
        type: u2
      - id: num_inode_bitmap_blocks
        type: u2
      - id: num_zone_bitmap_blocks
        type: u2
      - id: first_data_zone
        type: u2
      - id: size_log_zone
        type: u2
      - id: max_size
        type: u2
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
      - id: length
        type: u2
      - id: time
        type: u2
      - id: gid
        type: u2
      - id: links
        type: u2
      - id: direct_zones
        type: u2
        repeat: expr
        repeat-expr: 7
      - id: indirect_zone
        type: u2
      - id: double_indirect_zone
        type: u2
