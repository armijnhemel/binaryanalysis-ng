meta:
  id: android_fbpk
  title: Android FBPK
  license: Apache-2.0
  encoding: UTF-8
  endian: le
doc-ref: https://github.com/anestisb/qc_image_unpacker/blob/master/src/packed_image.h
seq:
  - id: header
    type: header
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: header.num_entries

types:
  header:
    seq:
      - id: magic
        contents: "FBPK"
      - id: version
        type: u4
      - id: img_version
        size: 68
      - id: num_entries
        type: u4
      - id: total_file_size
        type: u4
  entry:
    seq:
      - id: type
        type: u4
      - id: partition_name
        size: 32
        type: strz
      - id: padding1
        type: u4
      - id: len_partition
        type: u4
      - id: padding2
        type: u4
      - id: next_offset
        type: u4
      - id: checksum
        type: u4
      - id: partition
        size: len_partition
        type:
          switch-on: type
          cases:
            0: fbpt
      - id: padding3
        size: next_offset - _io.pos
        if: next_offset <= _root.header.total_file_size
  fbpt:
    seq:
      - id: magic
        contents: "FBPT"
      - id: type
        type: u4
        enum: fbpt_types
      - id: lun
        type: u4
      - id: unknown1
        size: 4
      - id: num_partitions
        type: u4
      - id: unknown2
        size: 37
      - id: padding
        size: 3
      - id: entries
        type: fbpt_entry
        repeat: eos
  fbpt_entry:
    seq:
      - id: size
        type: u4
      - id: unknown
        size: 4
      - id: attributes
        type: u4
      - id: partition_name
        size: 36
        type: strz
      - id: type_guid
        size: 37
        type: strz
      - id: partition_guid
        size: 37
        type: strz
      - id: padding
        size: 2

enums:
  fbpt_types:
    0: mbr
    1: gpt
    2: gpt_backup
