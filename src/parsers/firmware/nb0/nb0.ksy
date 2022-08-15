meta:
  id: nb0
  title: Android nb0 format
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc: |
  A barely documented older Android firmware format used on FreeScale/NXP
  devices.

  Test file (if you can find it): "ViewPad 7 Firmware v3_42_uk.zip". The
  firmware update for the Acer BeTouch E130 also contains it, although it is
  hidden deep inside the firmware.

  Note: the extension "nb0' is also often used for Windows CE files.
doc-ref:
  - https://github.com/yohanes/Acer-BeTouch-E130-RUT/blob/master/nb0.h
  - https://github.com/yohanes/Acer-BeTouch-E130-RUT/blob/master/nb0.c
seq:
  - id: num_entries
    type: u4
    valid:
      min: 1
      max: _root._io.size / 64
      # the size can never be more than the
      # amount of bytes in the file.
  - id: entries
    type: entry
    size: 64
    repeat: until
    repeat-until: _index == num_entries - 1
instances:
  partitions:
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
