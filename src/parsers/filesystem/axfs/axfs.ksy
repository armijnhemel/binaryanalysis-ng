meta:
  id: axfs
  title: AXFS
  license: CC0-1.0
  endian: be
  encoding: ASCII
doc: |
  <https://en.wikipedia.org/wiki/AXFS>
seq:
  - id: magic
    contents: [0x48, 0xa0, 0xe4, 0xcd]
  - id: signature
    contents: "Advanced XIP FS\x00"
  - id: sha1
    size: 40
  - id: compressed_block_size
    -orig-id: cblock_size
    type: u4
    doc: maximum size of the block being compressed
  - id: num_files
    -orig-id: files
    type: u8
    doc: number of inodes/files in fs
  - id: len_image
    -orig-id: size
    type: u8
    doc: total image size
  - id: num_nodes
    -orig-id: blocks
    type: u8
    doc: number of nodes in fs
  - id: mmap_size
    type: u8
    doc: size of the memory mapped part of image
  - id: ofs_strings_region
    -orig-id: strings
    type: u8
    doc: offset to strings region descriptor
  - id: ofs_xip
    -orig-id: xip
    type: u8
    doc: offset to xip region descriptor
  - id: ofs_byte_aligned
    -orig-id: byte_aligned
    type: u8
    doc: offset to the byte aligned region descriptors
  - id: ofs_compressed
    -orig-id: compressed
    type: u8
    doc: offset to the compressed region descriptors
  - id: ofs_node_type
    -orig-id: node_type
    type: u8
    doc: offset to node type region descriptors
  - id: ofs_node_index
    -orig-id: node_index
    type: u8
    doc: offset to node index region descriptors
  - id: ofs_cnode
    -orig-id: cnode_offset
    type: u8
    doc: offset to cnode offset region descriptors
  - id: ofs_cnode_index
    -orig-id: cnode_index
    type: u8
    doc: offset to cnode index region descriptors
  - id: ofs_banode
    -orig-id: banode_offset
    type: u8
    doc: offset to banode offset region descriptors
  - id: ofs_cblock
    -orig-id: cblock_offset
    type: u8
    doc: offset to cblock offset region descriptors
  - id: ofs_inode_file_size
    -orig-id: inode_file_size
    type: u8
    doc: offset to inode file size descriptors
  - id: ofs_inode_name
    -orig-id: inode_name_offset
    type: u8
    doc: offset to inode num_entries region descriptors
  - id: ofs_inode_num_entries
    -orig-id: inode_num_entries
    type: u8
    doc: offset to inode num_entries region descriptors
  - id: ofs_inode_mode_index
    -orig-id: inode_mode_index
    type: u8
    doc: offset to inode mode index region descriptors
  - id: ofs_node_array_index
    -orig-id: inode_array_index
    type: u8
    doc: offset to inode node index region descriptors
  - id: ofs_modes
    -orig-id: modes
    type: u8
    doc: offset to mode mode region descriptors
  - id: ofs_uids
    -orig-id: uids
    type: u8
    doc: offset to mode uid index region descriptors
  - id: ofs_gids
    -orig-id: gids
    type: u8
    doc: offset to mode gid index region descriptors
  - id: major_version
    type: u1
  - id: minor_version
    type: u1
  - id: sub_version
    type: u1
  - id: compression_type
    type: u1
  - id: timestamp
    type: u8
  - id: page_shift
    type: u1
types:
  data_region:
    # struct axfs_region_desc_onmedia
    seq:
      - id: ofs_fs
        -orig-id: fsoffset
        type: u8
      - id: size
        type: u8
      - id: compressed_size
        type: u8
      - id: max_index
        type: u8
      - id: table_byte_depth
        type: u1
      - id: incode
        type: u1
    doc: on media struct describing a data region
enums:
  node_types:
    0: xip
    1: compressed
    2: byte_aligned
