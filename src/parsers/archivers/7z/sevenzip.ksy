meta:
  id: sevenzip
  title: 7z
  file-extension:
    - 7z
  license: CC0-1.0
  ks-version: 0.9
  encoding: UTF-8
  endian: le
seq:
  - id: header
    type: signature_header
types:
  signature_header:
    seq:
      - id: magic
        contents: ['7z', 0xbc, 0xaf, 0x27, 0x1c]
      - id: major_version
        type: u1
        valid: 0
      - id: minor_version
        type: u1
      - id: start_header_crc
        type: u4
      - id: start_header
        size: 20
        type: start_header
  start_header:
    seq:
      - id: ofs_next_header
        type: u8
      - id: len_next_header
        type: u8
      - id: next_header_crc
        type: u4
    instances:
      next_header:
        pos: ofs_next_header + _root.header._sizeof
        size: len_next_header
        io: _root._io
