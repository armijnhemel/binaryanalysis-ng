meta:
  id: romfs_ambarella
  title: Ambarella ROMFS format
  license: CC0-1.0
  endian: le
doc-ref: http://web.archive.org/web/20190402224117/https://courses.cs.ut.ee/MTAT.07.022/2015_spring/uploads/Main/karl-report-s15.pdf (section 4.1)
seq:
  - id: num_files
    type: u4
  - id: magic
    size: 4
    contents: [0x8a, 0x32, 0xfc, 0x66]
  - id: padding
    size: 2040
  - id: file_headers
    type: file_header
    repeat: expr
    repeat-expr: num_files
    # TODO: padding
types:
  file_header:
    seq:
      - id: name
        type: strz
        encoding: ASCII
        size: 116
      - id: ofs_data
        type: u4
      - id: len_data
        type: u4
      - id: magic
        size: 4
        contents: [0x76, 0xab, 0x87, 0x23]
    instances:
      data:
        pos: ofs_data
        size: len_data
