meta:
  id: zcomax
  title: ZComax firmware
  license: GPL-2.0-only
  endian: le
doc-ref: https://raw.githubusercontent.com/openwrt/openwrt/f705008d7e696/tools/firmware-utils/src/mkzcfw.c
seq:
  - id: header
    type: header(0x6d726966)
    # 'firm'
  - id: firmware_body
    type: firmware_body
    size: header.len_body - header.unknown._sizeof
  - id: tail
    type: tail
types:
  header:
    params:
      - id: valid_contents
        type: u4
    seq:
      - id: magic
        type: u4
        valid: valid_contents
      - id: len_body
        type: u4
      - id: unknown
        size: 8
  tail:
    seq:
      - id: hardware_identifier
        type: u4
      - id: crc
        type: u4
  firmware_body:
    seq:
      - id: kernel
        type: kernel
      - id: rootfs
        type: rootfs
  kernel:
    seq:
      - id: header
        type: header(0x676d694b)
        # 'Kimg'
      - id: body
        size: header.len_body - header.unknown._sizeof
      - id: tail
        type: tail
  rootfs:
    seq:
      - id: header
        type: header(0x676d6952)
        # 'Rimg'
      - id: body
        size: header.len_body - header.unknown._sizeof
      - id: tail
        type: tail
