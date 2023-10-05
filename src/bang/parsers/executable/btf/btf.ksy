meta:
  id: btf
  title: BTF
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://docs.kernel.org/bpf/btf.html
seq:
  - id: header
    type: header
  - id: type_section
    size: header.rest_of_header.len_type_section
    #type: type_section
  - id: string_section
    size: header.rest_of_header.len_string_section
    type: string_section
types:
  header:
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
        type: rest_of_header
        size: len_header - magic._sizeof - version._sizeof - flags._sizeof - len_header._sizeof
    types:
      rest_of_header:
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
      bit-endian: le
    seq:
      - id: vlen
        type: b16
      - id: unused1
        type: b8
      - id: kind
        type: b5
        enum: kind
      - id: unused2
        type: b2
      - id: kind_flag
        type: b1
  type_section:
    seq:
      - id: btf_types
        type: btf_type
        repeat: eos
  btf_type:
    -webide-representation: "{info.kind}"
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
            kind::union: btf_kind_union(info.vlen)
            kind::enum: btf_kind_enum(info.vlen)
            kind::enum64: btf_kind_enum64(info.vlen)
            kind::function_proto: btf_kind_function_proto(info.vlen)
            kind::variable: btf_kind_variable
            kind::section: btf_kind_section(info.vlen)
            kind::decl_tag: btf_kind_decl_tag
    instances:
      name:
        pos: ofs_name
        io: _root.string_section._io
        type: strz
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
  btf_kind_decl_tag:
    seq:
      - id: component_idx
        type: u4
  btf_kind_enum:
    params:
      - id: num_enums
        type: b15
    seq:
      - id: enums
        type: btf_enum
        repeat: expr
        repeat-expr: num_enums
    types:
      btf_enum:
        seq:
          - id: ofs_name
            type: u4
          - id: val
            type: s4
        instances:
          name:
            pos: ofs_name
            io: _root.string_section._io
            type: strz
  btf_kind_enum64:
    params:
      - id: num_enums
        type: b15
    seq:
      - id: enums
        type: btf_enum64
        repeat: expr
        repeat-expr: num_enums
    types:
      btf_enum64:
        seq:
          - id: ofs_name
            type: u4
          - id: val_lo32
            type: u4
          - id: val_hi32
            type: u4
        instances:
          name:
            pos: ofs_name
            io: _root.string_section._io
            type: strz
  btf_kind_function_proto:
    params:
      - id: num_function_protos
        type: b15
    seq:
      - id: function_protos
        type: btf_function_proto
        repeat: expr
        repeat-expr: num_function_protos
    types:
      btf_function_proto:
        seq:
          - id: ofs_name
            type: u4
          - id: type
            type: u4
        instances:
          name:
            pos: ofs_name
            io: _root.string_section._io
            type: strz
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
  btf_kind_section:
    params:
      - id: num_sections
        type: b15
    seq:
      - id: sections
        type: btf_section
        repeat: expr
        repeat-expr: num_sections
    types:
      btf_section:
        seq:
          - id: type
            type: u4
          - id: offset
            type: u4
          - id: size
            type: u4
  btf_kind_union:
    params:
      - id: num_members
        type: b15
    seq:
      - id: members
        type: member
        repeat: expr
        repeat-expr: num_members
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
        instances:
          name:
            pos: ofs_name
            io: _root.string_section._io
            type: strz
  btf_kind_variable:
    seq:
      - id: linkage
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
