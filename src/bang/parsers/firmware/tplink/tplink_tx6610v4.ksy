meta:
  id: tplink_tx6610v4
  title: TP-Link TX6610v4 firmware update
  license: MIT
  endian: be
  encoding: UTF-8
doc-ref:
  - https://github.com/alexandernst/TPLink-TX6610-firmware-tools
seq:
  - id: header
    type: header
  - id: kernel
    size: header.rest_of_header.len_kernel
  - id: padding
    #size: 0x150000 - header.rest_of_header.len_kernel - header.len_header
    size: 1376256 - header.rest_of_header.len_kernel - header.len_header
  - id: rootfs
    size: header.rest_of_header.len_rootfs
  - id: padding2
    #size: header.rest_of_header.len_file - (0x150000 + header.rest_of_header.len_rootfs)
    size: header.rest_of_header.len_file - (1376256 + header.rest_of_header.len_rootfs)
  - id: trailer
    size: 232
types:
  header:
    seq:
      - id: magic
        contents: '2RDH'
      - id: len_header
        type: u4
      - id: rest_of_header
        size: len_header - len_header._sizeof - magic._sizeof
        type: rest_of_header
  rest_of_header:
    seq:
      - id: len_file
        type: u4
      - id: crc32
        type: u4
      - id: name
        size: 32
        type: strz
      - id: customer_version
        size: 32
        type: strz
      - id: len_kernel
        type: u4
      - id: len_rootfs
        type: u4
        valid:
          max: len_file - 0x150000
      - id: len_ctrom
        type: u4
      - id: model
        size: 32
        type: strz
      - id: unknown
        size: 4
      - id: reserved
        size-eos: true
