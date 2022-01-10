meta:
  id: qt_resource
  title: Qt resource
  file-extension: rcc
  license: CC-1.0
  endian: be
  encoding: UTF-8
doc-ref: <https://github.com/qt/qtbase/blob/5.4/src/tools/rcc/rcc.cpp>
seq:
  - id: header
    type: header
  - id: data_block
    type: entry_block
    size: header.ofs_tree - len_name_table - header._sizeof
  - id: name_table
    type: name_table
    size: len_name_table
  - id: tree
    type: tree_entry
    repeat: expr
    repeat-expr: data_block.entries.size + 1
    # one entry for each element, plus one for the root
    # of the tree
instances:
  len_name_table:
    value: header.ofs_tree - header.ofs_name_table

types:
  header:
    seq:
      - id: magic
        contents: "qres"
      - id: version
        type: u4
      - id: ofs_tree
        type: u4
      - id: ofs_data
        type: u4
      - id: ofs_name_table
        type: u4
  entry_block:
    seq:
      - id: entries
        type: entry
        repeat: eos
  entry:
    seq:
      - id: len_data
        type: u4
      - id: data
        size: len_data
  name_table:
    seq:
      - id: entries
        type: name_table_entry
        repeat: eos
  name_table_entry:
    seq:
      - id: len_name
        type: u2
      - id: hash
        type: u4
        # Qt hash
      - id: name
        size: len_name * 2
  tree_entry:
    seq:
      - id: name_offset
        type: u4
      - id: flags
        type: u2
      - id: num_children
        type: u4
      - id: ofs_first_child
        type: u4
