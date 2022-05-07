meta:
  id: android_fbpk
  title: Android FBPK
  license: Apache-2.0
  encoding: UTF-8
  endian: le
doc-ref:
  - https://github.com/anestisb/qc_image_unpacker/blob/master/src/packed_image.h
  - https://source.android.com/devices/bootloader/tools/pixel/fw_unpack/fbpack.py
seq:
  - id: header
    type: header
  - id: body
    type:
      switch-on: header.version
      cases:
        1: bodyv1
        2: bodyv2
types:
  header:
    seq:
      - id: magic
        contents: "FBPK"
      - id: version
        type: u4
        valid:
          any-of: [1, 2]
  bodyv1:
    seq:
      - id: img_version
        size: 68
      - id: num_entries
        type: u4
      - id: total_file_size
        type: u4
      - id: entries
        type: entryv1
        repeat: until
        repeat-until: (_index == num_entries - 1) or _io.eof
        if: num_entries != 0
  bodyv2:
    seq:
      - id: len_header
        type: u4
      - id: len_entry
        type: u4
      - id: chip_id
        size: 16
      - id: img_version
        size: 64
      - id: slot_type
        type: u4
      - id: data_align
        type: u4
      - id: num_entries
        type: u4
      - id: total_file_size
        type: u4
      - id: entries
        type: entryv2(total_file_size)
        size: len_entry
        repeat: expr
        repeat-expr: num_entries
  entryv1:
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
      - id: padding3
        size: next_offset - _io.pos
        if: next_offset <= _parent.total_file_size
  entryv2:
    params:
      - id: total_file_size
        type: u4
    seq:
      - id: type
        size: 4
      - id: partition_name
        size: 36
        type: strz
      - id: product_name
        size: 40
        type: strz
      - id: ofs_partition
        type: u8
        valid:
          max: total_file_size
      - id: len_partition
        type: u8
        valid:
          max: total_file_size - ofs_partition
      - id: slotted
        type: u4
      - id: crc32
        size: 4
    instances:
      partition:
        pos: ofs_partition
        size: len_partition
        io: _root._io
      partition_parsed:
        pos: ofs_partition
        size: len_partition
        io: _root._io
        type:
          switch-on: magic
          cases:
            0x54504246: fbptv2
      magic:
        pos: ofs_partition
        type: u4
        io: _root._io
        if: len_partition >= 4
  fbptv1:
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
  fbptv2:
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
      - id: unknown3
        size: 4
      - id: entries
        type: fbpt_entryv2
        repeat: expr
        repeat-expr: num_partitions
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
  fbpt_entryv2:
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
      - id: file_system_type
        size: 14

enums:
  fbpt_types:
    0: mbr
    1: gpt
    2: gpt_backup
