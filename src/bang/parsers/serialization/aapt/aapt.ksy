meta:
  id: aapt
  title: Android Asset Packaging Tool
  license: CC0
  endian: le
  encoding: UTF-8
doc-ref:
  - https://android.googlesource.com/platform/frameworks/base/+/0ba2a37eafd802d240e602bfdc74fc4cfe0c07cd/tools/aapt2/formats.md
seq:
  - id: magic
    contents: "AAPT"
  - id: version
    type: u4
    valid: 1
    doc: The version of the container format.
  - id: num_entries
    -orig-id: entry_count
    type: u4
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: num_entries
types:
  entry:
    seq:
      - id: entry_type
        type: u4
        enum: entry_types
        valid:
          any-of:
            - entry_types::table
            - entry_types::file
        doc: |
          The type of the entry. This can be one of two types:
          RES_TABLE (0x00000000) or RES_FILE (0x00000001).
      - id: len_data
        -orig-id: entry_length
        type: u8
        doc: |
          The length of the data that follows. Do not use if entry_type
          is RES_FILE; this value may be wrong.
      - id: data
        type:
          switch-on: entry_type
          cases:
            entry_types::table: table(len_data)
            entry_types::file: file
      - id: padding
        size: (- _io.pos % 4)
  table:
    params:
      - id: len_data
        type: u8
    seq:
      - id: data
        size: len_data
  file:
    seq:
      - id: len_header
        type: u4
        doc: The size of the header field.
      - id: len_data
        type: u8
        doc: The size of the data field.
      - id: header
        size: len_header
        doc: The serialized Protobuf message aapt.pb.internal.CompiledFile.
      - id: padding1
        size: (-len_header % 4)
      - id: data
        size: len_data
      - id: padding2
        size: (-len_data % 4)
enums:
  entry_types:
    0: table
    1: file
