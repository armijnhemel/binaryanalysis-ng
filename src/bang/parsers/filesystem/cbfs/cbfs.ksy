meta:
  id: cbfs
  title: Coreboot File System
  license: CC0
  endian: be
  encoding: ASCII
doc-ref:
  - https://www.coreboot.org/CBFS
types:
  header:
    seq:
      - id: magic
        contents: "ORBC"
      - id: version
        type: u4
      - id: len_rom
        type: u4
      - id: len_boot_block
        type: u4
      - id: align
        type: u4
        valid: 64
      - id: cbfs_offset
        type: u4
      - id: architecture
        type: u4
      - id: pad
        size: 4
  component:
    seq:
      - id: header
        type: component_header
      - id: name
        type: strz
        size: header.offset - header._sizeof
      - id: data
        size: header.len_data
  component_header:
    seq:
      - id: magic
        contents: "LARCHIVE"
      - id: len_data
        type: u4
      - id: type
        type: u4
        enum: payload_types
      - id: checksum
        type: u4
      - id: offset
        type: u4
  payload:
    seq:
      - id: type
        type: u4
        enum: payload_segments
      - id: compression
        type: u4
        enum: compression
      - id: offset
        type: u4
      - id: load_addr
        type: u8
      - id: len
        type: u4
      - id: len_mem
        type: u4
    enums:
      payload_segments:
        0x45444f43: code
        0x41544144: data
        0x20535342: bss
        0x41524150: params
        0x52544e45: entry
enums:
  payload_types:
    0x10: stage
    0x20: payload
    0x30: option_roms
  compression:
    0: no_compression
    1: lzma
    2: nrv2b
