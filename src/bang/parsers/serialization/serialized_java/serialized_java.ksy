meta:
  id: serialized_java
  title: Serialized Java (blocks only)
  license: CC0-1.0
  endian: be
  encoding: UTF-8
doc-ref: https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html
seq:
  - id: magic
    contents: [0xac, 0xed]
  - id: version
    type: u2
    valid: 5
  - id: blocks
    type: block
    repeat: until
    repeat-until: _io.eof or not _.is_valid
    # This is ugly, as it eats one extra byte, so an external
    # program processing this could should take this into account
types:
  block:
    seq:
      - id: symbol
        type: u1
        enum: symbols
      - id: body
        type: block_body
        if: is_valid
    instances:
      is_valid:
        value: symbol == symbols::block_data or symbol == symbols::block_data_long
  block_body:
    seq:
      - id: len_data
        type:
          switch-on: _parent.symbol
          cases:
            symbols::block_data: u1
            symbols::block_data_long: u4
      - id: data
        size: len_data
enums:
  symbols:
    0x70: null_symbol
    0x71: reference
    0x72: class_description
    0x73: object_symbol
    0x74: string_symbol
    0x75: array_symbol
    0x76: class_symbol
    0x77: block_data
    0x78: end_block_data
    0x79: reset
    0x7a: block_data_long
    0x7b: exception_symbol
    0x7c: long_string
    0x7d: proxy_class_description
    0x7e: enum_symbol
