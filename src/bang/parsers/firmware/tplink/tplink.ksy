meta:
  id: tplink
  title: TP-Link firmware update
  license: GPL-2.0-or-later
  endian: be
  encoding: UTF-8
doc-ref:
  - https://github.com/rampageX/firmware-mod-kit/blob/104c8213f66d3aa9f9a2449f5d80638ad13c30dc/src/tpl-tool/src/tpl-tool.c
seq:
  - id: header
    size: len_header
    type: header
  - id: data
    size: header.len_image - len_header
    type: dummy
types:
  dummy: {}
  header:
    seq:
      - id: header_version
        type: u4
        valid: 0x01000000
      - id: vendor
        size: 24
        type: strz
      - id: image_version
        size: 36
        type: strz
      - id: product_id
        type: u4
        enum: device_info
      - id: product_version
        type: u4
      - id: padding_1
        size: 4
        contents: [0, 0, 0, 0]
      - id: image_checksum
        size: 16
      - id: padding_2
        size: 4
        contents: [0, 0, 0, 0]
      - id: kernel_checksum
        size: 16
      - id: padding_3
        size: 4
        contents: [0, 0, 0, 0]
      - id: kernel_load_address
        type: u4
      - id: kernel_entry_point
        type: u4
      - id: len_image
        type: u4
      - id: ofs_kernel
        type: u4
        valid:
          max: len_image
      - id: len_kernel
        type: u4
        valid:
          max: len_image
      - id: ofs_rootfs
        type: u4
        valid:
          max: len_image
      - id: len_rootfs
        type: u4
        valid:
          max: len_image
      - id: ofs_bootloader
        type: u4
        valid:
          max: len_image
      - id: len_bootloader
        type: u4
        valid:
          max: len_image
      - id: firmware_version_major
        type: u2
      - id: firmware_version_minor
        type: u2
      - id: firmware_version_point
        type: u2
      - id: padding_4
        size: 354
instances:
  len_header:
    value: 512
  bootloader:
    pos: header.ofs_bootloader
    size: header.len_bootloader
    io: _root.data._io
    if: header.len_bootloader != 0
  kernel:
    pos: header.ofs_kernel - _root.len_header
    size: header.len_kernel
    io: _root.data._io
  rootfs:
    pos: header.ofs_rootfs - _root.len_header
    size: header.len_rootfs
    io: _root.data._io
enums:
  device_info:
    0x08010001: tl_wa801nd_v1
    0x09010001: tl_wa901nd_v1
    0x09010002: tl_wa901nd_v2
    0x09410002: tl_wr941nd_v2
    0x09410004: tl_wr941nd_v4
    0x10420001: tl_wr1042nd_v1
    0x10430001: tl_wr1043nd_v1
    0x25430001: tl_wr2543n_v1
    0x43000001: tl_wdr4300_v1
