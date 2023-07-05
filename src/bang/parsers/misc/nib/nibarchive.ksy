meta:
  id: nibarchive
  title: NibArchive
  file-extension: nib
  license: CC-1.0
  #imports:
    #- /common/vlq_base128_le
  endian: le
  encoding: UTF-8
doc-ref: https://github.com/matsmattsson/nibsqueeze/blob/master/NibArchive.md
seq:
  - id: header
    type: header
instances:
  objects:
    pos: header.ofs_objects
    type: obj
    repeat: expr
    repeat-expr: header.num_objects
  keys:
    pos: header.ofs_keys
    type: key
    repeat: expr
    repeat-expr: header.num_keys
  #values:
    #pos: header.ofs_values
    #type: value
    #repeat: expr
    #repeat-expr: header.num_values
  class_names:
    pos: header.ofs_class_names
    type: class_name
    repeat: expr
    repeat-expr: header.num_class_names
types:
  header:
    seq:
      - id: magic
        contents: "NIBArchive"
      - id: constant_1
        type: u4
        valid: 1
      - id: constant_2
        type: u4
        #valid: 9
      - id: num_objects
        type: u4
      - id: ofs_objects
        type: u4
      - id: num_keys
        type: u4
      - id: ofs_keys
        type: u4
      - id: num_values
        type: u4
      - id: ofs_values
        type: u4
      - id: num_class_names
        type: u4
      - id: ofs_class_names
        type: u4
  key:
    seq:
      - id: len_name
        type: compressed_integer
      - id: name
        size: len_name.value
        type: str
  obj:
    seq:
      - id: class_name_index
        type: compressed_integer
      - id: values_index
        type: compressed_integer
      - id: value_count
        type: compressed_integer
  class_name:
    seq:
      - id: len_name
        type: compressed_integer
      - id: num_other_ints
        type: compressed_integer
      - id: other_ints
        type: u4
        repeat: expr
        repeat-expr: num_other_ints.value
      - id: name
        size: len_name.value
        type: strz

  compressed_integer:
    seq:
      - id: groups
        type: group
        repeat: until
        repeat-until: not _.has_next
    types:
      group:
        doc: |
          One byte group, clearly divided into 7-bit "value" chunk and 1-bit "continuation" flag.
        seq:
          - id: b
            type: u1
        instances:
          has_next:
            value: (b & 0b1000_0000) == 0
            doc: If true, then we have more bytes to read
          value:
            value: b & 0b0111_1111
            doc: The 7-bit (base128) numeric value chunk of this group
    instances:
      len:
        value: groups.size
      value:
        value: >-
          groups[0].value
          + (len >= 2 ? (groups[1].value << 7) : 0)
          + (len >= 3 ? (groups[2].value << 14) : 0)
          + (len >= 4 ? (groups[3].value << 21) : 0)
          + (len >= 5 ? (groups[4].value << 28) : 0)
          + (len >= 6 ? (groups[5].value << 35) : 0)
          + (len >= 7 ? (groups[6].value << 42) : 0)
          + (len >= 8 ? (groups[7].value << 49) : 0)
        doc: Resulting value as normal integer
