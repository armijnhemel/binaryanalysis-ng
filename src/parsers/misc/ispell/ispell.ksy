meta:
  id: ispell
  title: ispell
  license: CC-1.0
  endian: le
  encoding: UTF-8
doc: |
  ispell version 2 hash files
seq:
  - id: magic
    contents: [0x02, 0x96]
  - id: compile_options
    type: u2
  - id: max_string_chars
    type: u2
  - id: max_string_char_len
    type: u2
  - id: compound_min
    type: u2
  - id: compound_bit
    type: s2
  - id: len_string_table
    -orig-id: stringsize
    type: u4
  - id: len_language_string_table
    -orig-id: lstringsize
    type: u4
  - id: num_hash_entries
    -orig-id: tblsize
    type: u4
  - id: num_sfx_entries
    -orig-id: stblsize
    type: u4
  - id: num_pfx_entries
    -orig-id: ptblsize
    type: u4
  - id: sort_val
    type: u4
    doc: Largest sort ID assigned
  - id: num_str_chars
    -orig-id: nstrchars
    type: u4
  - id: num_str_char_types
    -orig-id: nstrchartype
    type: u4
  - id: ofs_strtype
    -orig-id: strtypestart
    type: u4
    doc: Start of strtype table
  - id: nroff_chars
    contents: "().\*"
    doc: Nroff special characters
  - id: tex_chars
    contents: "()[]{}<>\$*.%"
    doc: TeX special characters
  - id: compound_flag
    type: u1
  - id: default_hardflag
    type: u1
  - id: flag_marker
    size: 1
    doc: Start-of-flags char
  - id: sort_order
    type: u2
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: lower_conversion_table
    type: u2
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: upper_conversion_table
    type: u2
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: word_chars
    size: 1 
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: upper_chars
    size: 1 
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: lower_chars
    size: 1 
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: boundary_chars
    size: 1 
    repeat: expr
    repeat-expr: set_size + max_string_chars
  - id: string_starts
    size: 1 
    repeat: expr
    repeat-expr: set_size
  - id: string_chars
    size: max_string_char_len + 1
    repeat: expr
    repeat-expr: max_string_chars
  - id: string_dups
    type: u4
    repeat: expr
    repeat-expr: max_string_chars
  - id: group_numbers
    type: s4
    repeat: expr
    repeat-expr: max_string_chars
  - id: magic2
    size: 2
    #valid: magic
instances:
  set_size:
    value: 256
