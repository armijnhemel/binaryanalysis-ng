meta:
  id: dwarf
  title: DWARF
  endian: le
  license: CC0-1.0
  ks-version: 0.9
seq:
  - id: compilation_units
    type: compilation_unit
    repeat: eos
types:
  compilation_unit:
    seq:
      - id: header
        type: debug_line_header
      - id: data
        size: header.length - header._sizeof + header.length._sizeof
  debug_line_header:
    seq:
      - id: length
        type: u4
      - id: version
        type: u2
      - id: len_header
        type: u4
      - id: min_instruction_length
        type: u1
      - id: default_is_stmt
        type: u1
      - id: line_base
        type: s1
      - id: line_range
        type: u1
      - id: opcode_base
        type: u1
      - id: opcode_lengths
        type: u1
        repeat: expr
        repeat-expr: 12
