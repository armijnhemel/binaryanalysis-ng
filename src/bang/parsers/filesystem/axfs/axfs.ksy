meta:
  id: axfs
  title: Advanced XIP file system
  license: CC0-1.0
  encoding: UTF-8
  endian: be
doc-ref:
  - https://github.com/jaredeh/axfs
seq:
  - id: superblock
    type: superblock
types:
  superblock:
    seq:
      - id: magic
        contents: [0x48, 0xA0, 0xE4, 0xCD]
      - id: signature
        contents: "Advanced XIP FS\x00"
      - id: digest
        size: 40
      - id: cblock_size
        type: u4
      - id: num_files
        type: u8
      - id: len_image
        type: u8
      - id: num_blocks
        type: u8
      - id: mmap_size
        type: u8
      - id: ofs_strings_region
        type: u8
      - id: ofs_xip_region
        type: u8
      - id: ofs_byte_aligned_region
        type: u8
      - id: ofs_compressed_region
        type: u8
      - id: ofs_node_type_region
        type: u8
      - id: ofs_node_index_region
        type: u8
      - id: ofs_cnode_offset_region
        type: u8
      - id: ofs_cnode_index_region
        type: u8
      - id: ofs_banode_offset_region
        type: u8
      - id: ofs_cblock_offset_region
        type: u8
      - id: ofs_inode_file_size_region
        type: u8
      - id: ofs_inode_name_region
        type: u8
      - id: ofs_inode_num_entries_region
        type: u8
      - id: ofs_inode_mode_index_region
        type: u8
      - id: ofs_inode_array_index_region
        type: u8
      - id: ofs_modes_region
        type: u8
      - id: ofs_uids_region
        type: u8
      - id: ofs_gids_region
        type: u8
      - id: version
        type: version
      - id: compression_type
        type: u1
        valid: 0
      - id: padding
        size: 4
        doc: padding as the time stamp is 8 byte aligned
      - id: timestamp
        type: u8
      - id: page_shift
        type: u1
    instances:
      strings_region:
        pos: ofs_strings_region
        type: region_desc
      xip_region:
        pos: ofs_xip_region
        type: region_desc
      byte_aligned_region:
        pos: ofs_byte_aligned_region
        type: region_desc
      compressed_region:
        pos: ofs_compressed_region
        type: region_desc
      node_type_table:
        pos: ofs_node_type_region
        type: region_desc
      node_index_table:
        pos: ofs_node_index_region
        type: region_desc
      cnode_offset_table:
        pos: ofs_cnode_offset_region
        type: region_desc
      cnode_index_table:
        pos: ofs_cnode_index_region
        type: region_desc
      banode_offset_table:
        pos: ofs_banode_offset_region
        type: region_desc
      cblock_offset_table:
        pos: ofs_cblock_offset_region
        type: region_desc
      inode_file_size_table:
        pos: ofs_inode_file_size_region
        type: region_desc
      inode_name_table:
        pos: ofs_inode_name_region
        type: region_desc
      inode_num_entries_table:
        pos: ofs_inode_num_entries_region
        type: region_desc
      inode_mode_index:
        pos: ofs_inode_mode_index_region
        type: region_desc
      inode_array_index_table:
        pos: ofs_inode_array_index_region
        type: region_desc
      modes_table:
        pos: ofs_modes_region
        type: region_desc
      uid_table:
        pos: ofs_uids_region
        type: region_desc
      gid_table:
        pos: ofs_gids_region
        type: region_desc
  version:
    seq:
      - id: major
        type: u1
      - id: minor
        type: u1
      - id: sub
        type: u1
  region_desc:
    seq:
      - id: ofs_fs
        type: u8
      - id: len_data
        type: u8
      - id: len_compressed
        type: u8
      - id: max_index
        type: u8
      - id: table_byte_depth
        type: u1
      - id: incore
        type: u1
    instances:
      data:
        pos: ofs_fs
        size: len_data
