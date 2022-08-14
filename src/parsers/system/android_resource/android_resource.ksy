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
      - id: body
        size: header.len_chunk - header._sizeof
        type:
          switch-on: header.type
          cases:
            resource_types::string_pool: string_pool
            resource_types::table: table
            resource_types::table_package: table_package
            resource_types::xml: xml
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
            - resource_types::xml_start_namespace
            - resource_types::xml_end_namespace
            - resource_types::xml_start_element
            - resource_types::xml_end_element
            - resource_types::xml_cdata
            - resource_types::xml_last_chunk
            - resource_types::xml_resource_map
            - resource_types::table_package
            - resource_types::table_type
            - resource_types::table_type_spec
            - resource_types::table_library
            - resource_types::table_overlayable
            - resource_types::table_overlayable_policy
            - resource_types::table_staged_alias
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
      - id: res_tables
        type: chunk
        repeat: expr
        repeat-expr: _parent.header.num_table_package

  # Table package
  table_package:
    seq:
      - id: header
        type: table_package_header
        #size: _parent.header.len_header - _parent.header._sizeof
      - id: body
        #type: table_package_body
        size-eos: true
    instances:
      len_header:
        value: _parent.header.len_header
  table_package_header:
    seq:
      - id: package_id
        type: u4
      - id: name
        size: 256
        # utf-16
      - id: type_strings
        type: u4
      - id: last_public_type
        type: u4
      - id: key_strings
        type: u4
      - id: last_public_key
        type: u4
      - id: type_id_offset
        type: u4

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
      strings:
        value: body.strings
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
        valid:
          max: _root._io.size / 4
      - id: num_styles
        type: u4
        valid:
          max: _root._io.size / 4
      - id: flags
        type: u4
      - id: ofs_strings
        type: u4
        valid:
          max: _root._io.size
        doc: Index from header of the string data.
      - id: ofs_styles
        type: u4
        valid:
          max: _root._io.size
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
        if: is_utf8
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

  # XML
  xml:
    seq:
      - id: header
        size: _parent.header.len_header - _parent.header._sizeof
      - id: body
        type: xml_body
        size-eos: true
  xml_body:
    seq:
      - id: nodes
        type: chunk
        repeat: eos

enums:
  resource_types:
    0: null_type
    1: string_pool
    2: table
    3: xml

    # Chunk types in RES_XML_TYPE
    0x100: xml_start_namespace  # also: first_chunk
    0x101: xml_end_namespace
    0x102: xml_start_element
    0x103: xml_end_element
    0x104: xml_cdata
    0x17f: xml_last_chunk
    0x180: xml_resource_map

    # Chunk types in RES_TABLE_TYPE
    0x200: table_package
    0x201: table_type
    0x202: table_type_spec
    0x203: table_library
    0x204: table_overlayable
    0x205: table_overlayable_policy
    0x206: table_staged_alias
