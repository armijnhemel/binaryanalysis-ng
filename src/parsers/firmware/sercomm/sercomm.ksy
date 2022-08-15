meta:
  id: sercomm
  title: Sercomm firmware
  license: GPL-2.0-only
  endian: le
  encoding: ASCII
doc: |
  A simple 512 byte header that can be found on devices made by Sercomm,
  an ODM from Taiwan. Examples are several NETGEAR devices, such as the
  NETGEAR DGND4000.

  The header does not contain any information about the data that follows
  and only has a one byte checksum.
doc-ref:
  - https://raw.githubusercontent.com/openwrt/openwrt/3f5619f259de/tools/firmware-utils/src/mksercommfw.c
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/563a19d5c/src/binwalk/magic/firmware
seq:
  - id: magic
    contents: "sErCoMm"
  - id: version
    size: 4
  - id: hardware_id
    type: strz
    size: 34
  - id: hardware_version
    type: strz
    size: 10
  - id: software_version
    size: 8
  - id: magic2
    contents: "sErCoMm"
  - id: padding_bytes
    type: padding_byte
    repeat: expr
    repeat-expr: 441
  - id: checksum
    size: 1
types:
  padding_byte:
    seq:
      - id: padding_byte
        contents: [0x00]
