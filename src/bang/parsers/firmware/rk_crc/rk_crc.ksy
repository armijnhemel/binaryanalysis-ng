meta:
  id: rk_crc
  title: Rockchip CRC wrapper
  license: BSD2
  endian: le
  encoding: UTF-8
doc-ref:
  - https://github.com/neo-technologies/rkflashtool/blob/master/rkcrc.c
seq:
  - id: magic
    contents: "KRNL"
  - id: len_data
    type: u4
  - id: data
    size: len_data
  - id: crc
    type: u4
