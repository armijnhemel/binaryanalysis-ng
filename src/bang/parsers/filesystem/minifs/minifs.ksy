meta:
  id: minifs
  title: MINIFS
  license: CC0-1.0
  endian: be
  encoding: ASCII
doc: |
  MINIFS is a file system found in certain TP-Link firmware files, such as
  RE450(V4)_210531.zip
seq:
  - id: header
    type: header
    size: 32
  - id: filenames
    type: filenames
    size: header.len_filenames

types:
  header:
    seq:
      - id: magic
        contents: "MINIFS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      - id: unknown1
        type: u4
      - id: unknown2
        type: u4
      - id: unknown3
        type: u4
      - id: len_filenames
        type: u4
  filenames:
    seq:
      - id: filename
        type: strz
        repeat: eos
