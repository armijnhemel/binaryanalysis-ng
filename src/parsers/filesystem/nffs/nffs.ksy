meta:
  id: nffs
  title: Apache Mynewt NFFS
  license: CC0-1.0
  endian: le
  encoding: ASCII
doc: |
  Apache Mynewt
seq:
  - id: areas
    type: area
    repeat: expr
    repeat-expr: 1
types:
  area:
    seq:
      - id: magic_and_length
        type: magic_and_length
      - id: header
        type: header
        size: magic_and_length.len_area - magic_and_length._sizeof
  magic_and_length:
    seq:
      - id: magic1
        contents: [0xe2, 0x31, 0x8a, 0xb9]
      - id: magic2
        contents: [0x8c, 0x42, 0xb0, 0x7f]
      - id: magic3
        contents: [0x53, 0x82, 0xe0, 0xac]
      - id: magic4
        contents: [0x8e, 0xfc, 0x85, 0xb1]
      - id: len_area
        type: u4
  header:
    seq:
      - id: version
        type: u1
        valid: 0
      - id: garbage_collection_count
        type: u1
      - id: reserved
        type: u1
      - id: area_id
        type: u1
