meta:
  id: btf
  title: BTF
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://docs.kernel.org/bpf/btf.html
seq:
  - id: magic
    contents: [0x9f, 0xeb]
  - id: version
    type: u1
  - id: flags
    type: u1
  - id: len_header
    type: u4
  - id: rest_of_header
    type: header
    size: len_header - magic._sizeof - version._sizeof - flags._sizeof - len_header._sizeof
  - id: type_section
    size: rest_of_header.len_type_section
    #type: type_section
  - id: string_section
    size: rest_of_header.len_string_section
    type: string_section
types:
  header:
    seq:
      - id: ofs_type_section
        type: u4
      - id: len_type_section
        type: u4
      - id: ofs_string_section
        type: u4
      - id: len_string_section
        type: u4
  info:
    meta:
      bit-endian: be
    seq:
      - id: kind_flag
        type: b1
      - id: unused2
        type: b2
      - id: kind
        type: b4
        enum: kind
      - id: unused1
        type: b8
      - id: vlen
        type: b15
  type_section:
    seq:
      - id: btf_types
        type: btf_type
        repeat: eos
  btf_type:
    seq:
      - id: ofs_name
        type: u4
      - id: info
        type: info
      - id: size_or_type
        type: u4
      - id: data
        type:
          switch-on: info.kind
          cases:
            kind::integer: btf_kind_int
            kind::array: btf_kind_array
            kind::union: btf_kind_union
  btf_kind_array:
    seq:
      - id: btf_array
        type: btf_array
    types:
      btf_array:
        seq:
          - id: type
            type: u4
            enum: kind
          - id: index_type
            type: u4
          - id: num_elems
            type: u4
          - id: elems
            type:
              switch-on: type
              cases:
                kind::union: btf_kind_union
  btf_kind_int:
    seq:
      - id: int_flags
        type: u4
    instances:
      int_encoding:
        value: (int_flags & 0x0f000000) >> 24
        enum: bit_encodings
      int_offset:
        value: (int_flags & 0x00ff0000) >> 16
      int_bits:
        value: int_flags & 0x000000ff
    enums:
      bit_encodings:
        1: signed
        2: char
        4: bool
  btf_kind_union:
    seq:
      - id: members
        type: member
        repeat: expr
        repeat-expr: 1
    types:
      member:
        seq:
          - id: ofs_name
            type: u4
          - id: type
            type: u4
            enum: kind
          - id: member_offset
            type: u4
  string_section:
    seq:
      - id: strings
        type: strz
        repeat: eos
enums:
  kind:
    0: void
    1: integer
    2: pointer
    3: array
    4: struct
    5: union
    6: enum
    7: forward
    8: typedef
    9: volatile
    10: const
    11: restrict
    12: function
    13: function_proto
    14: variable
    15: section
    16: floating_point
    17: decl_tag
    18: type_tag
    19: enum64
