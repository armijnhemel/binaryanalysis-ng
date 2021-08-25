meta:
  id: rockchip_resource
  title: Rockchip formats
  license: CC-1.0
  endian: le
  encoding: UTF-8
doc-ref: https://gitlab.com/postmarketOS/pmbootstrap/-/issues/2031
seq:
  - id: header
    type: header
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: header.num_files

types:
  header:
    seq:
      - id: magic
        contents: "RSCE"
      - id: version
        -orig-id: RSCEver
        type: u2
      - id: file_table_version
        -orig-id: RSCEfileTblVer
        type: u2
      - id: len_header
        -orig-id: HdrBlkSize
        type: u1
        # in blocks
      - id: ofs_file_table
        -orig-id: FileTblBlkOffset
        type: u1
        # in blocks
      - id: len_file_table_entry
        -orig-id: FileTblRecBlkSize
        type: u1
      - id: unknown1
        size: 1
      - id: num_files
        -orig-id: FileCount
        type: u4
      - id: reserved
        type: padding_byte
        repeat: expr
        repeat-expr: 496
  entry:
    seq:
      - id: magic
        contents: "ENTR"
      - id: name
        size: 256
        type: strz
      - id: ofs_file_block
        -orig-id: FileBlkOffset
        type: u4
      - id: len_file
        -orig-id: FileSize
        type: u4
      - id: reserved
        size: 244
    instances:
      data:
        pos: ofs_file_block * 512
        size: len_file
  padding_byte:
    seq:
      - id: padding_byte
        contents: [0x00]
