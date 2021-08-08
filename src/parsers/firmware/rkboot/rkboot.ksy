meta:
  id: rkboot
  title: Rockchip boot format
  license: GPL-2.0-or-later
  endian: le
  encoding: UTF-8
doc-ref:
  - https://github.com/rockchip-linux/rkdeveloptool/blob/master/RKBoot.h#L7
  - https://github.com/rockchip-linux/rkdeveloptool/blob/master/RKBoot.cpp#L212
  - https://github.com/rockchip-linux/rkdeveloptool/blob/master/boot_merger.h#L122
seq:
  - id: magic
    contents: "BOOT"
  - id: size
    type: u2
  - id: header
    type: header
    size: size - magic._sizeof - size._sizeof
instances:
  entries_471:
    pos: header.ofs_entries_471
    size: header.len_entry_471
    type: rk_entry(1)
    repeat: expr
    repeat-expr: header.num_entries_471
  entries_472:
    pos: header.ofs_entries_472
    size: header.len_entry_472
    type: rk_entry(2)
    repeat: expr
    repeat-expr: header.num_entries_472
  entries_loader:
    pos: header.ofs_entries_loader
    size: header.len_entry_loader
    type: rk_entry(4)
    repeat: expr
    repeat-expr: header.num_entries_loader
types:
  header:
    seq:
      - id: version
        type: u4
      - id: merge_version
        type: u4
      - id: release_time
        type: rktime
      - id: supported_chip
        type: u4
        enum: rkdevice
      - id: num_entries_471
        type: u1
      - id: ofs_entries_471
        type: u4
      - id: len_entry_471
        type: u1
      - id: num_entries_472
        type: u1
      - id: ofs_entries_472
        type: u4
      - id: len_entry_472
        type: u1
      - id: num_entries_loader
        type: u1
      - id: ofs_entries_loader
        type: u4
      - id: len_entry_loader
        type: u1
      - id: flags
        type: u1
      - id: rc4_flags
        type: u1
      - id: reserved
        size: 57
  rktime:
    seq:
      - id: year
        type: u2
      - id: month
        type: u1
      - id: day
        type: u1
      - id: hour
        type: u1
      - id: minute
        type: u1
      - id: second
        type: u1
  rk_entry:
    params:
      - id: valid_version
        type: u4
    seq:
      - id: size
        type: u1
      - id: entry_type
        type: u4
        valid: valid_version
      - id: name
        size: 40
      - id: ofs_data
        type: u4
      - id: len_data
        type: u4
      - id: data_delay
        type: u4
    instances:
      data:
        pos: ofs_data
        io: _root._io
        size: len_data
enums:
  rkdevice:
    0: none
    0x10: rk27
    0x20: rk28
    0x30: rknano
    0x40: rkcrown
    0x50: rk29
    0x60: rk30
    0x70: rk31
    0x80: rk32
