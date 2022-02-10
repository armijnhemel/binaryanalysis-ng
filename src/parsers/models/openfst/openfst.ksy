meta:
  id: openfst
  title: OpenFst
  file-extension: fst
  license: CC0-1.0
  ks-version: 0.9
  encoding: UTF-8
  endian: le
doc: |
  OpenFst parser for a subset of OpenFst files, inspired by:
  https://github.com/steveash/jopenfst/pull/11/files
seq:
  - id: magic
    contents: [0xd6, 0xfd, 0xb2, 0x7e]
  - id: len_fst_type
    type: u4
  - id: fst_type
    -orig-id: fsttype
    type: strz
    size: len_fst_type
    valid: '"vector"'
  - id: len_arc_type
    type: u4
  - id: arc_type
    -orig-id: fsttype
    type: strz
    size: len_arc_type
    valid: '"standard"'
  - id: version
    -orig-id: kFileVersion
    type: u4
    valid: 2
  - id: flags
    type: u4
  - id: properties
    type: u8
  - id: start
    type: u8
  - id: num_states
    type: s8
    valid:
      min: 0
  - id: num_arcs
    type: u8
  - id: input_symbol_table
    type: symbol_table
    if: has_input_symbol_table
  - id: output_symbol_table
    type: symbol_table
    if: has_output_symbol_table
  - id: states
    type: state
    repeat: expr
    repeat-expr: num_states
  #- id: arcs
    #type: arc
    #repeat: expr
    #repeat-expr: num_arc
instances:
  has_input_symbol_table:
    value: flags & 0x01 == 0x01
  has_output_symbol_table:
    value: flags & 0x02 == 0x02
  is_aligned:
    value: flags & 0x04 == 0x04
types:
  symbol_table:
    seq:
      - id: magic
        contents: [0x74, 0xfb, 0xb2, 0x7e]
      - id: len_name
        type: u4
      - id: name
        type: strz
        size: len_name
      - id: available_key
        type: u8
      - id: num_symbols
        type: u8
      - id: symbols
        type: symbol
        repeat: expr
        repeat-expr: num_symbols
  symbol:
    seq:
      - id: len_name
        type: u4
      - id: name
        type: strz
        size: len_name
      - id: key
        type: u8
  state:
    seq:
      - id: weight
        type: u4
      - id: num_arcs
        type: u8
      - id: arcs
        type: arc
        repeat: expr
        repeat-expr: num_arcs
  arc:
    seq:
      - id: input_label_idx
        type: u4
      - id: output_label_idx
        type: u4
      - id: weight
        type: u4
      - id: next_state_idx
        type: u4
