meta:
  id: android_resource
  title: Android resource files
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc-ref:
  https://android.googlesource.com/platform/frameworks/base.git/+/2fedba9a32d9e92344eaf6e9faf5b43e1bc2ae70/libs/androidfw/include/androidfw/ResourceTypes.h#202
seq:
  - id: resource
    type: chunk
types:
  chunk:
    seq:
      - id: header
        type: header
      - id: rest_of_chunk
        size: header.len_chunk - header._sizeof
        type:
          switch-on: header.type
          cases:
            resource_types::string_pool: string_pool
            resource_types::table: table
  header:
    seq:
      - id: type
        type: u2
        enum: resource_types
        valid:
          any-of:
            - resource_types::null_type
            - resource_types::string_pool
            - resource_types::table
            - resource_types::xml
      - id: len_header
        type: u2
      - id: len_chunk
        type: u4

  # Table
  table:
    seq:
      - id: header
        type: table_header
        size: _parent.header.len_header - _parent.header._sizeof
      - id: body
        type: table_body
        size-eos: true
    instances:
      len_header:
        value: _parent.header.len_header
  table_header:
    seq:
      - id: num_table_package
        type: u4
  table_body:
    seq:
      - id: string_pool
        type: chunk

  # String pool
  string_pool:
    seq:
      - id: header
        type: string_pool_header
        size: _parent.header.len_header - _parent.header._sizeof
      - id: body
        type: string_pool_body
        size-eos: true
    instances:
      len_header:
        value: _parent.header.len_header
  string_pool_body:
    seq:
      - id: string_offsets
        type: u4
        repeat: expr
        repeat-expr: _parent.header.num_strings
      - id: style_offsets
        type: u4
        repeat: expr
        repeat-expr: _parent.header.num_styles
    instances:
      strings:
        type: pool_string(_index, ofs_strings, _parent.header.is_utf8)
        repeat: expr
        repeat-expr: _parent.header.num_strings
      styles:
        type: pool_style(_index, ofs_styles)
        repeat: expr
        repeat-expr: _parent.header.num_styles
      ofs_strings:
        value: _parent.header.ofs_strings - _parent.len_header
      ofs_styles:
        value: _parent.header.ofs_styles - _parent.len_header
  string_pool_header:
    seq:
      - id: num_strings
        type: u4
      - id: num_styles
        type: u4
      - id: flags
        type: u4
      - id: ofs_strings
        type: u4
        doc: Index from header of the string data.
      - id: ofs_styles
        type: u4
        doc: Index from header of the style data.
    instances:
      is_sorted:
        value: flags & 0x1 == 0x1
      is_utf8:
        value: flags & 0x100 == 0x100
  pool_string:
    params:
      - id: i
        type: u4
      - id: ofs_strings
        type: u4
      - id: is_utf8
        type: bool
    instances:
      string:
        pos: ofs_strings + _parent.string_offsets[i]
        type: strz
        io: _parent._io
  pool_style:
    params:
      - id: i
        type: u4
      - id: ofs_styles
        type: u4
    instances:
      style:
        pos: ofs_styles + _parent.style_offsets[i]
        type: string_pool_span_array
        io: _parent._io
  string_pool_span_array:
    seq:
      - id: string_pool_span
        type: string_pool_span
        repeat: until
        repeat-until: _.reference == 0xffffffff
  string_pool_span:
    seq:
      - id: reference
        type: u4
      - id: first_char
        type: u4
        if: reference != 0xffffffff
      - id: last_char
        type: u4
        if: reference != 0xffffffff

enums:
  resource_types:
    0: null_type
    1: string_pool
    2: table
    3: xml

  xml_types:
    # Chunk types in RES_XML_TYPE
    0x100: start_namespace  # also: first_chunk
    0x101: end_namespace
    0x102: start_element
    0x103: end_element
    0x104: cdata
    0x17f: last_chunk
    0x180: resource_map

  table_types:
    # Chunk types in RES_TABLE_TYPE
    0x200: package
    0x201: type
    0x202: type_spec
    0x203: library
    0x204: overlayable
    0x205: overlayable_policy
    0x206: staged_alias
