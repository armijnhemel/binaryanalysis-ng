meta:
  id: nb0
  title: Android nb0 format
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc: |
  A barely documented older Android firmware format used on NXP devices.
doc-ref:
  - https://github.com/yohanes/Acer-BeTouch-E130-RUT/blob/master/nb0.h
  - https://github.com/yohanes/Acer-BeTouch-E130-RUT/blob/master/nb0.c
seq:
  - id: num_entries
    type: u4
  - id: entries
    type: entry
    size: 64
    repeat: until
    repeat-until: _index == num_entries - 1
    if: num_entries != 0
instances:
  partition:
    type: partition_type(_index)
    repeat: expr
    repeat-expr: num_entries
types:
  entry:
    seq:
      - id: ofs_partition
        type: u4
      - id: len_partition
        type: u4
      - id: unknown1
        type: u4
      - id: unknown2
        type: u4
      - id: name
        size: 48
        type: strz
  partition_type:
    params:
      - id: i
        type: u4
    instances:
      body:
        pos: _root.entries[i].ofs_partition + _root.num_entries * sizeof<entry> + _root.num_entries._sizeof
        size: _root.entries[i].len_partition
