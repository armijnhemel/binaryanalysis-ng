meta:
  id: rockchip
  title: Rockchip formats
  license: BSD
  endian: le
  encoding: UTF-8
doc-ref: https://raw.githubusercontent.com/linux-rockchip/rkflashtool/0a5ad3a81/rkunpack.c
seq:
  - id: rockchip
    type:
      switch-on: magic
      cases:
        '"RKFW"': rkfw
        '"RKAF"': rkaf
instances:
  magic:
    pos: 0
    size: 4
    type: str
types:
  rkaf:
    seq:
      - id: magic
        size: 4
        contents: "RKAF"
      - id: file_size
        type: u4
      - id: unknown
        size: 64
        # model and id
      - id: manufacturer
        size: 64
        type: strz
      - id: num_files
        type: u4
        valid:
          expr: num_files * 112 < file_size
      - id: rockchip_files
        type: rockchip_file
        size: 112
        repeat: expr
        repeat-expr: num_files
  rockchip_file:
    seq:
      - id: name
        size: 32
        type: strz
      - id: path
        size: 32
        type: strz
      - id: unknown
        size: 32
      - id: ofs_image
        -orig-id: ioff
        type: u4
      - id: noff
        type: u4
      - id: len_image
        -orig-id: isize
        type: u4
      - id: len_file
        -orig-id: fsize
        type: u4
    instances:
      data:
        pos: ofs_image
        io: _parent._io
        size: len_file
        if: ofs_image != 0
  rkfw:
    seq:
      - id: magic
        size: 4
        contents: "RKFW"
      - id: unknown
        size: 2
      - id: version
        size: 4
      - id: unknown1
        size: 4
      - id: date_information
        size: 7
      - id: chip_id
        type: u1
        enum: chip_identifiers
      - id: unknown2
        size: 3
      - id: ofs_boot_image
        type: u4
      - id: len_boot_image
        type: u4
      - id: ofs_image
        type: u4
      - id: len_image
        type: u4
    instances:
      boot_image:
        pos: ofs_boot_image
        size: len_boot_image
      rkaf:
        pos: ofs_image
        size: len_image
        type: rkaf
enums:
  chip_identifiers:
    0x50: rk29xx
    0x60: rk30xx
    0x70: rk31xx
    0x80: rk32xx
    0x41: rk3368
