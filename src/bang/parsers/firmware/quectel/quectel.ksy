meta:
  id: quectel
  title: Quectel firmware image
  license: CC0-1.0
  endian: le
  encoding: UTF-8
seq:
  - id: header
    size: 0x1000
    type: header
  - id: header2
    # the size is probably incorrect
    size: 0x2e4
    type: header2
  - id: header3
    type: header3
types:
  header:
    seq:
      - id: magic
        contents: 'Quec'
      - id: unknown_1
        size: 4
      - id: unknown_2
        size: 4
      - id: num_bytes
        # number of bytes after this??
        type: u4
      - id: name_1
        size: 32
        type: strz
      - id: name_2
        size: 64
        type: strz
      - id: unknown_3
        size: 32
      - id: num_partitions
        type: u4
      - id: partitions
        size: 24
        type: partition
        repeat: expr
        repeat-expr: num_partitions
    types:
      partition:
        seq:
          - id: partition_id
            type: u4
          - id: unknown_1
            type: u4
          - id: unknown_2
            type: u4
          - id: unknown_3
            type: u4
          - id: unknown_4
            type: u4
          - id: unknown_5
            type: u4
  header2:
    seq:
      - id: unknown_1
        size: 4
      - id: num_bytes
        # number of bytes after this? is this actually correct?
        type: u4
      - id: unknown_2
        size: 8
      - id: num_partitions
        type: u4
      - id: partitions
        size: 24
        type: partition
        repeat: expr
        repeat-expr: num_partitions
    types:
      partition:
        seq:
          - id: unknown_1
            type: u4
          - id: unknown_2
            type: u4
          - id: unknown_3
            type: u4
          - id: unknown_4
            type: u4
          - id: unknown_5
            type: u4
          - id: unknown_6
            type: u4
  header3:
    seq:
      - id: num_partitions
        type: u4
      - id: partitions
        size: 100
        type: partition
        repeat: expr
        repeat-expr: num_partitions
    types:
      partition:
        seq:
          - id: len_name
            type: u4
          - id: unknown_1
            type: u4
          - id: unknown_2
            type: u4
          - id: unknown_3
            type: u4
          - id: unknown_4
            type: u4
          - id: unknown_5
            type: u4
          - id: unknown_6
            type: u4
          - id: unknown_7
            type: u4
          - id: unknown_8
            type: u4
          - id: name
            size: len_name
            type: strz
