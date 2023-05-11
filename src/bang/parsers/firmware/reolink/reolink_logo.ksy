meta:
  id: reolink_logo
  title: Reolink Logo
  license: CC0-1.0
  endian: le
  encoding: UTF-8
seq:
  - id: header
    type: header
  - id: data
    size: header.len_file - header._sizeof
    type: dummy
instances:
  jpeg_1:
    io: data._io
    pos: header.ofs_jpeg_1 - header._sizeof
    size: header.len_jpeg_1
  jpeg_2:
    io: data._io
    pos: header.ofs_jpeg_2 - header._sizeof
    size: header.len_jpeg_2
types:
  dummy: {}
  header:
    seq:
      - id: magic
        contents: 'GLOR'
      - id: len_file
        type: u4
      - id: unknown
        type: u4
      - id: ofs_jpeg_1
        type: u4
      - id: ofs_jpeg_2
        type: u4
      - id: len_jpeg_1
        type: u4
      - id: len_jpeg_2
        type: u4
      - id: reserved
        size: 4
