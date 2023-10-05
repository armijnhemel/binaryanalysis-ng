meta:
  id: systemd_hwdb
  title: systemd hwdb.bin
  file-extension: bin
  xref:
    forensicswiki: Systemd
  license: LGPL-2.1-or-later
  encoding: UTF-8
  endian: le
seq:
  - id: header
    type: header
  - id: data
    size: header.len_file - len_header
    type: dummy
instances:
  len_header:
    value: header._sizeof
  root_node:
    io: data._io
    pos: header.ofs_nodes_root - len_header
    type: trie_node
  is_value_entry_v2:
    value: header.len_value_entry == 32
types:
  dummy: {}
  header:
    seq:
      - id: signature
        contents: "KSLPHHRH"
      - id: tool_version
        type: u8
      - id: len_file
        type: u8
      - id: len_header
        type: u8
      - id: len_node
        type: u8
      - id: len_child_entry
        type: u8
      - id: len_value_entry
        type: u8
        valid:
          any-of: [16, 32]
      - id: ofs_nodes_root
        type: u8
      - id: len_nodes
        type: u8
      - id: len_strings
        type: u8
  child_node:
    seq:
      - id: index
        type: u1
      - id: padding
        size: 7
      - id: ofs_child
        type: u8
    instances:
      child:
        io: _root.data._io
        pos: ofs_child - _root.len_header
        type: trie_node
  trie_node:
    seq:
      - id: ofs_prefix
        type: u8
      - id: num_children
        type: u1
      - id: padding
        size: 7
      - id: num_values
        type: u8
      - id: children_entries
        size: _root.header.len_child_entry
        type: child_node
        repeat: expr
        repeat-expr: num_children
      - id: value_entries
        type:
          switch-on: _root.is_value_entry_v2
          cases:
            false: value_entry
            true: value_entry_2
        repeat: expr
        repeat-expr: num_values
  value_entry:
    seq:
      - id: ofs_key
        type: u8
      - id: ofs_value
        type: u8
    instances:
      key:
        io: _root.data._io
        pos: ofs_key - _root.len_header
        type: strz
      value:
        io: _root.data._io
        pos: ofs_value - _root.len_header
        type: strz
  value_entry_2:
    seq:
      - id: ofs_key
        type: u8
      - id: ofs_value
        type: u8
      - id: ofs_filename
        type: u8
      - id: line_number
        type: u4
      - id: file_priority
        type: u2
      - id: padding
        size: 2
    instances:
      key:
        io: _root.data._io
        pos: ofs_key - _root.len_header
        type: strz
      value:
        io: _root.data._io
        pos: ofs_value - _root.len_header
        type: strz
      filename:
        io: _root.data._io
        pos: ofs_filename - _root.len_header
        type: strz
