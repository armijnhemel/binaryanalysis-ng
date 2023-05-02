meta:
  id: dwarfs
  title: DwarFS
  license: GPL-3.0-or-later
  encoding: UTF-8
  endian: le
doc-ref:
  - https://github.com/mhx/dwarfs/blob/main/doc/dwarfs-format.md
seq:
  - id: blocks
    type: block
    repeat: eos
types:
  block:
    seq:
      - id: magic
        contents: "DWARFS"
      - id: major
        type: u1
      - id: minor
        type: u1
      - id: sha512_256
        size: 32
      - id: xxhash
        size: 8
      - id: section_number
        type: u4
      - id: section_type
        type: u2
        enum: sections
      - id: compression_algorithm
        type: u2
        enum: compression
      - id: len_data
        type: u8
      - id: data
        size: len_data
enums:
  sections:
    0: block
    7: schema
    8: metadata
    9: index
  compression:
    0: no_compression
    1: lzma
    2: zstd
    3: lz4
    4: lz4hc
