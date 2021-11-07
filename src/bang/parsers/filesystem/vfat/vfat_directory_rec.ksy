meta:
  id: vfat_directory_rec
  endian: le
seq:
  - id: short_name
    size: 8
  - id: short_ext
    size: 3
  - id: attributes
    type: u1
  - id: attributes_cpm
    type: u1
  - id: create_time_ms
    type: u1
  - id: create_time
    type: u2
  - id: create_date
    type: u2
  - id: access_date
    type: u2
  - id: access_rights
    type: u2
  - id: modified_time
    type: u2
  - id: modified_date
    type: u2
  - id: start_clus
    type: u2
  - id: file_size
    type: u4
instances:
  is_lfn_entry:
    value: attributes == 0x0f
  lfn_part_seq_nr:
    pos: 0
    size: 1
  lfn_part1:
    pos: 1
    size: 10
  lfn_part2:
    pos: 0x0e
    size: 12
  lfn_part3:
    pos: 0x1c
    size: 4
  attr_reserved:
    value: attributes & 0x80
  attr_device:
    value: attributes & 0x40
  attr_archive:
    value: attributes & 0x20
  attr_subdirectory:
    value: attributes & 0x10
  attr_volume_label:
    value: attributes & 0x08
  attr_system:
    value: attributes & 0x04
  attr_hidden:
    value: attributes & 0x02
  attr_read_only:
    value: attributes & 0x01
 
