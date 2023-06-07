meta:
  id: bzip2
  title: Bzip2 header
  file-extension: bz2
  license: CC0-1.0
  encoding: UTF-8
  endian: be
doc-ref: https://raw.githubusercontent.com/dsnet/compress/master/doc/bzip2-format.pdf
seq:
  - id: header
    type: header
  - id: block_header
    type: block_header
types:
  header:
    seq:
      - id: magic
        contents: 'BZ'
      - id: version
        size: 1
        type: str
        valid: '"h"'
      - id: level_char
        type: str
        size: 1
        valid:
          any-of: ['"1"', '"2"', '"3"', '"4"', '"5"', '"6"', '"7"', '"8"', '"9"']
    instances:
      level:
        value: level_char.to_i
  block_header:
    seq:
      - id: signature
        contents: [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
      - id: crc
        type: u4
