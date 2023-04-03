meta:
  id: f2fs
  title: F2FS
  license: LGPL-2.1
  encoding: UTF-8
  endian: le
doc-ref:
  - https://elinux.org/images/1/12/Elc2013_Hwang.pdf
  - https://docs.kernel.org/filesystems/f2fs.html
seq:
  - id: data
    size: 1024
  - id: superblock
    type: superblock
types:
  version:
    seq:
      - id: major
        type: u2
      - id: minor
        type: u2
  superblock:
    seq:
      - id: magic
        type: u4
      - id: version
        type: version
      - id: log_sector_size
        type: u4
      - id: log_sectors_per_block
        type: u4
      - id: log_blocksize
        type: u4
      - id: log_blocks_per_segment
        type: u4
      - id: segments_per_section
        type: u4
      - id: sections_per_zone
        type: u4
      - id: ofs_checksum
        type: u4
        doc: checksum offset inside super block
      - id: num_blocks
        type: u8
        doc: total # of user blocks
      - id: num_sections
        type: u4
      - id: num_segments
        type: u4
      - id: num_segments_checkpoint
        type: u4
        doc: segments for checkpoint
      - id: num_segments_sit
        type: u4
        doc: segments for SIT
      - id: num_segments_nat
        type: u4
        doc: segments for NAT
      - id: num_segments_ssa
        type: u4
        doc: segments for SSA
      - id: num_segments_main
        type: u4
        doc: segments for main area
      - id: segment0_block_address
        type: u4
      - id: checkpoint_block_address
        type: u4
      - id: sit_block_address
        type: u4
      - id: nat_block_address
        type: u4
      - id: ssa_block_address
        type: u4
      - id: main_area_block_address
        type: u4
      - id: root_inode_numner
        type: u4
      - id: node_inode_numner
        type: u4
      - id: meta_inode_numner
        type: u4
      - id: uuid
        size: 16
      - id: volume_name
        size: 1024
      - id: extension_count
        type: u4
      - id: extension_list
        size: 8
        type: strz
        repeat: expr
        repeat-expr: 64
      - id: checkpoint_payload
        type: u4
      - id: kernel_version
        size: 256
        type: strz
      - id: initial_kernel_version
        size: 256
        type: strz
      - id: features
        type: u4
      - id: encryption_level
        type: u1
      - id: encrypt_password_salt
        size: 16
      - id: f2fs_devices
        type: f2fs_device
        repeat: expr
        repeat-expr: 8
      - id: qf_infos
        type: u4
        repeat: expr
        repeat-expr: 3
      - id: num_hot_extensions
        type: u1
      - id: filename_charset_encoding
        type: u2
      - id: filename_charset_encoding_flags
        type: u2
      - id: stop_checkpoint_reason
        size: 32
      - id: errors
        size: 16
      - id: reserved
        size: 258
      - id: crc
        type: u4
  f2fs_device:
    seq:
      - id: path
        size: 64
        type: strz
      - id: total_segments
        type: u4
