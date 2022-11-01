meta:
  id: dwarf_debug_line
  title: DWARF .debug_line
  imports:
    - /common/vlq_base128_le
  encoding: UTF-8
  endian: le
  license: CC0-1.0
  ks-version: 0.9
doc-ref: <https://dwarfstd.org/doc/DWARF4.pdf>
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
        type: data
  data:
    seq:
      - id: include_directories
        type: strz
        repeat: until
        repeat-until: _ == ''
      #- id: file_name_entries
      #  type: file_name_entry
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
      - id: max_operations_per_instruction
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
  file_name_entry:
    seq:
      - id: name
        type: strz
      - id: dir_index
        type: vlq_base128_le
      - id: time_of_last_modification
        type: vlq_base128_le
      - id: len_bytes
        type: vlq_base128_le
    instances:
      directory_index:
        value: dir_index.value
      last_modification_time:
        value: time_of_last_modification.value
      len_bytes_in_file:
        value: len_bytes.value
