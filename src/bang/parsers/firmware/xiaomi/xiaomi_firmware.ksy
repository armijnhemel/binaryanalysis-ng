meta:
  id: xiaomi_firmware
  title: Xiaomi firmware update
  license: GPL-2.0-or-later
  endian: le
  encoding: UTF-8
doc: |
  Test files: https://miuirom.org/miwifi/xiaomi-router-ax9000
doc-ref:
  - https://lxr.openwrt.org/source/firmware-utils/src/xiaomifw.c
  - https://forum.openwrt.org/t/openwrt-support-for-xiaomi-ax9000/98908/251
seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: magic
        type: u4
        enum: magic
        valid:
          any-of:
            - magic::header_1
            - magic::header_2
      - id: ofs_signature
        type: u4
      - id: crc32
        type: u4
      - id: unused
        size: 2
        contents: [0, 0]
      - id: rest_of_header
        type:
          switch-on: magic
          cases:
            magic::header_1: rest_of_header_1
            magic::header_2: rest_of_header_2
      - id: ofs_blobs
        type: blob_offset
        repeat: expr
        repeat-expr: 8
    instances:
      signature:
        io: _root._io
        pos: ofs_signature
        type: signature
  rest_of_header_1:
    seq:
      - id: device_id
        type: u2
        enum: device_ids
  rest_of_header_2:
    seq:
      - id: unused
        size: 2
        contents: [0, 0]
      - id: device_name
        size: 8
        type: strz
      - id: market
        size: 8
        type: strz
      - id: unknown
        size: 16
  signature:
    seq:
      - id: len_signature
        type: u4
      - id: padding
        size: 12
      - id: signature
        size: len_signature
  blob_offset:
    seq:
      - id: ofs_blob
        type: u4
    instances:
      blob:
        io: _root._io
        pos: ofs_blob
        type: blob
        if: ofs_blob != 0
  blob:
    seq:
      - id: magic
        contents: [0xbe, 0xba, 0x00, 0x00]
      - id: ofs_flash
        type: u4
      - id: len_data
        type: u4
      - id: blob_type
        type: u2
        enum: blob_type
      - id: unused
        type: u2
      - id: name
        size: 32
        type: strz
      - id: data
        size: len_data
enums:
  magic:
    0x31524448: header_1 # 'HDR1' chinese version (and presumably older international versions)
    0x32524448: header_2 # 'HDR2', international version
  device_ids:
    0x03: r1cm
    0x04: r2d
    0x05: r1cl
    0x07: r3
    0x08: r3d
    0x0d: r3g
    0x12: r4cm
    0x16: r2100
    0x25: ra70
  blob_type:
    0x01: uboot
    0x04: fw_uimage
    0x06: fw_os2
    0x07: fw_uimage2
