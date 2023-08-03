meta:
  id: f2fs
  title: F2FS
  license: LGPL-2.1
  encoding: UTF-8
  endian: le
doc: |
  Create a test file:

  $ dd if=/dev/zero bs=64M of=test.f2fs count=1
  $ mkfs.f2fs test.f2fs
doc-ref:
  - https://elinux.org/images/1/12/Elc2013_Hwang.pdf
  - https://docs.kernel.org/filesystems/f2fs.html
  - https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git/
seq:
  - id: superblock_segment
    type: superblock_segment
    size: segment_size
  - id: checkpoint_segment
    type: checkpoint_segment
    size: superblock_segment.superblock.num_segments_checkpoint * segment_size
  - id: segment_info
    size: superblock_segment.superblock.num_segments_sit * segment_size
  - id: node_address_table
    size: superblock_segment.superblock.num_segments_nat * segment_size
  - id: segment_summary_area
    size: superblock_segment.superblock.num_segments_ssa * segment_size
  - id: main_area
    size: superblock_segment.superblock.num_segments_main * segment_size
    type: main_area
instances:
  segment_size:
    value: 2097152
types:
  checkpoint_segment:
    seq:
      - id: checkpoint_and_bitmaps
        size: _root.segment_size
        type: checkpoint_and_bitmaps
      - id: checkpoint_and_bitmaps2
        size: _root.segment_size
        type: checkpoint_and_bitmaps
    instances:
      active:
        value: 'checkpoint_and_bitmaps.checkpoint.version > checkpoint_and_bitmaps2.checkpoint.version ? checkpoint_and_bitmaps : checkpoint_and_bitmaps2'
  superblock_segment:
    seq:
      - id: superblock
        size: 4096
        type: superblock
      - id: superblock_backup
        size: 4096
        type: superblock
  version:
    seq:
      - id: major
        type: u2
      - id: minor
        type: u2
  superblock:
    seq:
      - id: reserved
        size: 1024
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
        valid:
          # SB + 2 (CP + SIT + NAT) + SSA + MAIN
          min: 9
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
      - id: root_inode_number
        type: u4
      - id: node_inode_number
        type: u4
      - id: meta_inode_number
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
      - id: reserved_2
        size: 258
      - id: crc
        type: u4
    instances:
      blocksize:
        value: 1 << log_blocksize
      checkpoint_offset:
        value: blocksize * checkpoint_block_address
      sit_offset:
        value: blocksize * sit_block_address
      encrypted:
        value: features & 0x01 == 0x01
      blockzoned:
        value: features & 0x02 == 0x02
      atomic_write:
        value: features & 0x04 == 0x04
      extra_attrs:
        value: features & 0x08 == 0x08
      prj_quota:
        value: features & 0x10 == 0x10
      inode_checksum:
        value: features & 0x20 == 0x20
      flexible_inline_xattr:
        value: features & 0x40 == 0x40
      quota_ino:
        value: features & 0x80 == 0x80
      inode_crtime:
        value: features & 0x100 == 0x100
      lost_found:
        value: features & 0x200 == 0x200
      verity:
        value: features & 0x400 == 0x400
      superblock_checksum:
        value: features & 0x800 == 0x800
      casefold:
        value: features & 0x1000 == 0x1000
      compression:
        value: features & 0x2000 == 0x2000
      readonly:
        value: features & 0x4000 == 0x4000
  f2fs_device:
    seq:
      - id: path
        size: 64
        type: strz
      - id: total_segments
        type: u4
  checkpoint_and_bitmaps:
    seq:
      - id: checkpoint
        size: 192
        type: checkpoint
      - id: sit_version_bitmap
        size: checkpoint.sit_ver_bitmap_bytesize
      - id: nat_version_bitmap
        size: checkpoint.nat_ver_bitmap_bytesize
    instances:
      checksum:
        pos: checkpoint.ofs_checksum
        type: u4
  checkpoint:
    seq:
      - id: version
        type: u8
      - id: num_user_blocks
        type: u8
      - id: num_valid_blocks
        type: u8
      - id: num_reserved_blocks
        type: u4
      - id: num_overprovision_blocks
        type: u4
      - id: num_free_segments
        type: u4
      - id: cur_node_segment_numbers
        type: u4
        repeat: expr
        repeat-expr: 8
      - id: cur_node_block_offsets
        type: u2
        repeat: expr
        repeat-expr: 8
      - id: cur_data_segment_numbers
        type: u4
        repeat: expr
        repeat-expr: 8
      - id: cur_data_block_offsets
        type: u2
        repeat: expr
        repeat-expr: 8
      - id: flags
        type: u4
      - id: num_pack_total_blocks
        type: u4
      - id: data_summary_block_number
        type: u4
      - id: num_valid_nodes
        type: u4
      - id: num_valid_inodes
        type: u4
      - id: next_free_node
        type: u4
      - id: sit_ver_bitmap_bytesize
        type: u4
        #valid: 64
      - id: nat_ver_bitmap_bytesize
        type: u4
        #valid: 256
      - id: ofs_checksum
        type: u4
      - id: elapsed_time
        type: u8
      - id: alloc_type
        size: 16
    instances:
      unmount:
        value: flags & 0x01 == 0x01
      orphan_present:
        value: flags & 0x02 == 0x02
      compact_summary:
        value: flags & 0x04 == 0x04
      error:
        value: flags & 0x08 == 0x08
      fsck:
        value: flags & 0x10 == 0x10
      fastboot:
        value: flags & 0x20 == 0x20
      crc_recovery:
        value: flags & 0x40 == 0x40
      nat_bits:
        value: flags & 0x80 == 0x80
      trimmed:
        value: flags & 0x100 == 0x100
      no_crc_recovery:
        value: flags & 0x200 == 0x200
      large_nat_bitmap:
        value: flags & 0x400 == 0x400
      quota_need_fsck:
        value: flags & 0x800 == 0x800
      disabled:
        value: flags & 0x1000 == 0x1000
      resizefs:
        value: flags & 0x4000 == 0x4000
  extent:
    seq:
      - id: ofs_file
        type: u4
      - id: block_address
        type: u4
      - id: len_extent
        type: u4
  sit_entry:
    seq:
      - id: vblocks
        type: u2
      - id: valid_bitmap
        size: 64
      - id: mtime
        type: u8
  main_area:
    seq:
      - id: blocks
        size: 4096
        repeat: eos
  footer:
    seq:
      - id: node_id
        type: u4
      - id: inode_number
        type: u4
      - id: flag
        type: u4
      - id: checkpoint_version
        type: u8
      - id: next_block_address
        type: u4
  dir_entry:
    seq:
      - id: hash_code
        type: u4
      - id: inode_number
        type: u4
      - id: len_filename
        type: u2
      - id: file_type
        type: u1
        enum: file_types
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
    8: max
    9: orphan
    10: xattr
