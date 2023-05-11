meta:
  id: android_tzdata
  title: Android tzdata
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: be
  imports:
    - /system/timezone/tzif
doc-ref:
  - https://android.googlesource.com/platform/bionic/+/lollipop-mr1-dev/libc/tools/zoneinfo/ZoneCompactor.java
seq:
  - id: signature
    contents: "tzdata"
    # 'tzdata' followed by a year, but for Android this is always 20xx
  - id: year
    type: str
    size: 4
  - id: release
    type: strz
    size: 2
  - id: ofs_index
    type: u4
  - id: ofs_data
    type: u4
  - id: ofs_zonetab
    type: u4
instances:
  len_index:
    value: 'ofs_data < ofs_zonetab ? ofs_data - ofs_index : ofs_zonetab - ofs_index'
  index:
    pos: ofs_index
    size: len_index
    type: entries
  zonetab:
    pos: ofs_zonetab
    type: zonetab
    size-eos: true
types:
  entries:
    seq:
      - id: entries
        type: entry
        repeat: eos
  entry:
    seq:
      - id: zonename
        size: 40
        type: strz
      - id: ofs_timezone
        type: u4
      - id: len_timezone
        type: u4
      - id: raw_gmt_offset
        type: u4
    instances:
      tzif:
        pos: _root.ofs_data + ofs_timezone
        size: len_timezone
        type: tzif
        io: _root._io
      raw_tzif:
        pos: _root.ofs_data + ofs_timezone
        size: len_timezone
        io: _root._io
  zonetab:
    seq:
      - id: entries
        type: str
        terminator: 0x0a
        repeat: eos
