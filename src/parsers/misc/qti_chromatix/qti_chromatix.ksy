meta:
  id: qti_chromatix
  title: QTI Chromatix
  license: CC-1.0
  endian: le
  encoding: UTF-8
doc: A proprietary format from Qualcomm.
seq:
  - id: header
    type: header
  - id: data
    size: header.len_file - header._sizeof
types:
  header:
    seq:
      - id: signature
        contents: "QTI Chromatix Header"
      - id: unknown1
        size: 8
      - id: len_file
        type: u4
      - id: version
        type: version
      - id: unknown2
        size: 2
      - id: parser_signature
        type: parser_signature
  version:
    seq:
      - id: major
        type: u2
      - id: minor
        type: u2
      - id: sub
        type: u2
  parser_signature:
    seq:
      - id: signature
        contents: "Parameter Parser V"
      - id: version
        size: 5
        type: parser_version
      - id: space
        contents: ' '
      - id: date
        size: 12
        type: date
    types:
      date:
        seq:
          - id: parens_left
            contents: '('
          - id: date_string
            size: 10
            type: str
          - id: parens_right
            contents: ')'
      parser_version:
        seq:
          - id: major_str
            type: str
            terminator: 0x2e
          - id: minor_str
            type: str
            terminator: 0x2e
          - id: sub_str
            type: str
            size-eos: true
        instances:
          major:
            value: major_str.to_i
          minor:
            value: minor_str.to_i
          sub:
            value: sub_str.to_i
