meta:
  id: yara_db
  title: YARA rule set
  license: CC0-1.0
  endian: le
seq:
  - id: magic
    contents: "YARA"
  - id: version
    type: u1
  - id: num_buffers
    type: u1
  - id: buffers
    type: buffer
    repeat: expr
    repeat-expr: num_buffers
types:
  buffer:
    seq:
      - id: ofs_buffer
        type: u8
      - id: len_buffer
        type: u4
    instances:
      buffer_item:
        pos: ofs_buffer
        size: len_buffer
        io: _root._io
