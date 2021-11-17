meta:
  id: pfs_40
  title: PFS/0.9 with 40 byte path names
  license: CC0-1.0
  encoding: ASCII
  endian: le
doc-ref: http://web.archive.org/web/20140107233423/http://www.cba.si/pfs/_README
seq:
  - id: header
    type: header
  - id: entries
    type: entries
instances:
  files:
    type: data(_index, _io.pos)
    repeat: expr
    repeat-expr: header.num_entries
types:
  header:
    seq:
      - id: magic
        contents: ['PFS/0.9', 0]
      - id: padding
        contents: [0, 0, 0, 0, 0, 0]
      - id: num_entries
        type: u2
  entries:
    seq:
      - id: entries
        type: entry
        repeat: expr
        repeat-expr: _root.header.num_entries
  entry:
    seq:
      - id: name
        type: strz
        size: 40
      - id: unknown
        size: 4
      - id: ofs_file
        type: u4
        valid:
          max: _root._io.size
      - id: len_file
        type: u4
        valid:
          max: _root._io.size - ofs_file
  data:
    params:
      - id: index
        type: u4
      - id: root_pos
        type: u4
    instances:
      name:
        value: _root.entries.entries[index].name
      data:
        pos: pos
        size: _root.entries.entries[index].len_file
      pos:
        value: _root.entries.entries[index].ofs_file + root_pos
