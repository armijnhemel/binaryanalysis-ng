meta:
  id: dex
  title: Android Dalvik VM executable (dex)
  file-extension: dex
  xref:
    pronom: fmt/694
    wikidata: Q29000585
  tags:
    - android
    - executable
  license: Apache-2.0
  imports:
    - vlq_base128_le
  endian: le
doc: |
  Android OS applications executables are typically stored in its own
  format, optimized for more efficient execution in Dalvik virtual
  machine.

  This format is loosely similar to Java .class file format and
  generally holds the similar set of data: i.e. classes, methods,
  fields, annotations, etc.
doc-ref: https://source.android.com/devices/tech/dalvik/dex-format
seq:
  - id: header
    type: header_item
instances:
  string_ids:
    pos: header.string_ids_off
    type: string_id_item
    repeat: expr
    repeat-expr: header.string_ids_size
    doc: |
      string identifiers list.

      These are identifiers for all the strings used by this file, either for
      internal naming (e.g., type descriptors) or as constant objects referred to by code.

      This list must be sorted by string contents, using UTF-16 code point values
      (not in a locale-sensitive manner), and it must not contain any duplicate entries.
  type_ids:
    pos: header.type_ids_off
    type: type_id_item
    repeat: expr
    repeat-expr: header.type_ids_size
    doc: |
      type identifiers list.

      These are identifiers for all types (classes, arrays, or primitive types)
      referred to by this file, whether defined in the file or not.

      This list must be sorted by string_id index, and it must not contain any duplicate entries.
  proto_ids:
    pos: header.proto_ids_off
    type: proto_id_item
    repeat: expr
    repeat-expr: header.proto_ids_size
    doc: |
      method prototype identifiers list.

      These are identifiers for all prototypes referred to by this file.

      This list must be sorted in return-type (by type_id index) major order,
      and then by argument list (lexicographic ordering, individual arguments
      ordered by type_id index). The list must not contain any duplicate entries.
  field_ids:
    pos: header.field_ids_off
    type: field_id_item
    repeat: expr
    repeat-expr: header.field_ids_size
    doc: |
      field identifiers list.

      These are identifiers for all fields referred to by this file, whether defined in the file or not.

      This list must be sorted, where the defining type (by type_id index)
      is the major order, field name (by string_id index) is the intermediate
      order, and type (by type_id index) is the minor order.

      The list must not contain any duplicate entries.
  method_ids:
    pos: header.method_ids_off
    type: method_id_item
    repeat: expr
    repeat-expr: header.method_ids_size
    doc: |
      method identifiers list.

      These are identifiers for all methods referred to by this file,
      whether defined in the file or not.

      This list must be sorted, where the defining type (by type_id index
      is the major order, method name (by string_id index) is the intermediate
      order, and method prototype (by proto_id index) is the minor order.

      The list must not contain any duplicate entries.
  class_defs:
    pos: header.class_defs_off
    type: class_def_item
    repeat: expr
    repeat-expr: header.class_defs_size
    doc: |
      class definitions list.

      The classes must be ordered such that a given class's superclass and
      implemented interfaces appear in the list earlier than the referring class.

      Furthermore, it is invalid for a definition for the same-named class to
      appear more than once in the list.
  #call_site_ids:
  #  pos: header.???
  #  type: call_site_id_item
  #  repeat: expr
  #  repeat-expr: header.???
  #  doc: |
  #    call site identifiers list.
  #
  #    These are identifiers for all call sites referred to by this file,
  #    whether defined in the file or not.
  #
  #    This list must be sorted in ascending order of call_site_off.
  link_data:
    pos: header.link_off
    size: header.link_size
    doc: |
      data used in statically linked files.

      The format of the data in this section is left unspecified by this document.

      This section is empty in unlinked files, and runtime implementations may
      use it as they see fit.
  data:
    pos: header.data_off
    size: header.data_size
    doc: |
      data area, containing all the support data for the tables listed above.

      Different items have different alignment requirements, and padding bytes
      are inserted before each item if necessary to achieve proper alignment.
  map:
    pos: header.map_off
    type: map_list
types:
  header_item:
    seq:
      - id: magic
        contents: "dex\n"
      - id: version_str
        size: 4
        type: strz
        encoding: ascii
      - id: checksum
        type: u4
        doc: |
          adler32 checksum of the rest of the file (everything but magic and this field);
          used to detect file corruption
      - id: signature
        size: 20
        doc: |
          SHA-1 signature (hash) of the rest of the file (everything but magic, checksum,
          and this field); used to uniquely identify files
      - id: file_size
        type: u4
        doc: |
          size of the entire file (including the header), in bytes
      - id: header_size
        type: u4
        # guard: 0x70
        doc: |
          size of the header (this entire section), in bytes. This allows for at
          least a limited amount of backwards/forwards compatibility without
          invalidating the format.
      - id: endian_tag
        type: u4
        enum: endian_constant
      - id: link_size
        type: u4
        doc: |
          size of the link section, or 0 if this file isn't statically linked
      - id: link_off
        type: u4
        doc: |
          offset from the start of the file to the link section, or 0 if link_size == 0.
          The offset, if non-zero, should be to an offset into the link_data section.
          The format of the data pointed at is left unspecified by this document;
          this header field (and the previous) are left as hooks for use by runtime implementations.
      - id: map_off
        type: u4
        doc: |
          offset from the start of the file to the map item.
          The offset, which must be non-zero, should be to an offset into the data
          section, and the data should be in the format specified by "map_list" below.
      - id: string_ids_size
        type: u4
        doc: |
          count of strings in the string identifiers list
      - id: string_ids_off
        type: u4
        doc: |
          offset from the start of the file to the string identifiers list,
          or 0 if string_ids_size == 0 (admittedly a strange edge case).
          The offset, if non-zero, should be to the start of the string_ids section.
      - id: type_ids_size
        type: u4
        doc: |
          count of elements in the type identifiers list, at most 65535
      - id: type_ids_off
        type: u4
        doc: |
          offset from the start of the file to the type identifiers list,
          or 0 if type_ids_size == 0 (admittedly a strange edge case).
          The offset, if non-zero, should be to the start of the type_ids section.
      - id: proto_ids_size
        type: u4
        doc: |
          count of elements in the prototype identifiers list, at most 65535
      - id: proto_ids_off
        type: u4
        doc: |
          offset from the start of the file to the prototype identifiers list,
          or 0 if proto_ids_size == 0 (admittedly a strange edge case).
          The offset, if non-zero, should be to the start of the proto_ids section.
      - id: field_ids_size
        type: u4
        doc: |
          count of elements in the field identifiers list
      - id: field_ids_off
        type: u4
        doc: |
          offset from the start of the file to the field identifiers list,
          or 0 if field_ids_size == 0.
          The offset, if non-zero, should be to the start of the field_ids section.
      - id: method_ids_size
        type: u4
        doc: |
          count of elements in the method identifiers list
      - id: method_ids_off
        type: u4
        doc: |
          offset from the start of the file to the method identifiers list,
          or 0 if method_ids_size == 0.
          The offset, if non-zero, should be to the start of the method_ids section.
      - id: class_defs_size
        type: u4
        doc: |
          count of elements in the class definitions list
      - id: class_defs_off
        type: u4
        doc: |
          offset from the start of the file to the class definitions list,
          or 0 if class_defs_size == 0 (admittedly a strange edge case).
          The offset, if non-zero, should be to the start of the class_defs section.
      - id: data_size
        type: u4
        doc: |
          Size of data section in bytes. Must be an even multiple of sizeof(uint).
      - id: data_off
        type: u4
        doc: |
          offset from the start of the file to the start of the data section.
    enums:
      endian_constant:
        0x12345678: endian_constant
        0x78563412: reverse_endian_constant
  string_id_item:
    -webide-representation: "{value.data} (offs={string_data_off})"
    seq:
      - id: string_data_off
        type: u4
        doc: |
          offset from the start of the file to the string data for this item.
          The offset should be to a location in the data section, and the data
          should be in the format specified by "string_data_item" below.
          There is no alignment requirement for the offset.
    types:
      string_data_item:
        -webide-representation: "{data}"
        seq:
          - id: utf16_size
            type: vlq_base128_le
          - id: data
            size: utf16_size.value
            type: str
            encoding: ascii
    instances:
      value:
        pos: string_data_off
        type: string_data_item
        -webide-parse-mode: eager
  type_id_item:
    -webide-representation: "{type_name}"
    seq:
      - id: descriptor_idx
        type: u4
        doc: |
          index into the string_ids list for the descriptor string of this type.
          The string must conform to the syntax for TypeDescriptor, defined above.
    instances:
      type_name:
        value: _root.string_ids[descriptor_idx].value.data
        -webide-parse-mode: eager
  proto_id_item:
    -webide-representation: "shorty_idx={shorty_idx} return_type_idx={return_type_idx} parameters_off={parameters_off}"
    seq:
      - id: shorty_idx
        type: u4
        doc: |
          index into the string_ids list for the short-form descriptor string of this prototype.
          The string must conform to the syntax for ShortyDescriptor, defined above,
          and must correspond to the return type and parameters of this item.
      - id: return_type_idx
        type: u4
        doc: |
          index into the type_ids list for the return type of this prototype
      - id: parameters_off
        type: u4
        doc: |
          offset from the start of the file to the list of parameter types for this prototype,
          or 0 if this prototype has no parameters.
          This offset, if non-zero, should be in the data section, and the data
          there should be in the format specified by "type_list" below.
          Additionally, there should be no reference to the type void in the list.
    instances:
      shorty_desc:
        value: _root.string_ids[shorty_idx].value.data
        doc: short-form descriptor string of this prototype, as pointed to by shorty_idx
      params_types:
        io: _root._io
        pos: parameters_off
        type: type_list
        if: parameters_off != 0
        doc: list of parameter types for this prototype
      return_type:
        value: _root.type_ids[return_type_idx].type_name
        doc: return type of this prototype
  field_id_item:
    -webide-representation: "class_idx={class_idx} type_idx={type_idx} name_idx={name_idx}"
    seq:
      - id: class_idx
        type: u2
        doc: |
          index into the type_ids list for the definer of this field.
          This must be a class type, and not an array or primitive type.
      - id: type_idx
        type: u2
        doc: |
          index into the type_ids list for the type of this field
      - id: name_idx
        type: u4
        doc: |
          index into the string_ids list for the name of this field.
          The string must conform to the syntax for MemberName, defined above.
    instances:
      class_name:
        value: _root.type_ids[class_idx].type_name
        doc: the definer of this field
      type_name:
        value: _root.type_ids[type_idx].type_name
        doc: the type of this field
      field_name:
        value: _root.string_ids[name_idx].value.data
        doc: the name of this field
  method_id_item:
    -webide-representation: "class_idx={class_idx} proto_idx={proto_idx} name_idx={name_idx}"
    seq:
      - id: class_idx
        type: u2
        doc: |
          index into the type_ids list for the definer of this method.
          This must be a class or array type, and not a primitive type.
      - id: proto_idx
        type: u2
        doc: |
          index into the proto_ids list for the prototype of this method
      - id: name_idx
        type: u4
        doc: |
          index into the string_ids list for the name of this method.
          The string must conform to the syntax for MemberName, defined above.
    instances:
      class_name:
        value: _root.type_ids[class_idx].type_name
        doc: the definer of this method
      proto_desc:
        value: _root.proto_ids[proto_idx].shorty_desc
        doc: the short-form descriptor of the prototype of this method
      method_name:
        value: _root.string_ids[name_idx].value.data
        doc: the name of this method
  class_def_item:
    -webide-representation: "{access_flags} {type_name}"
    seq:
      - id: class_idx
        type: u4
        doc: |
          index into the type_ids list for this class.

          This must be a class type, and not an array or primitive type.
      - id: access_flags
        type: u4
        enum: class_access_flags
        doc: |
          access flags for the class (public, final, etc.).

          See "access_flags Definitions" for details.
      - id: superclass_idx
        type: u4
        doc: |
          index into the type_ids list for the superclass,
          or the constant value NO_INDEX if this class has no superclass
          (i.e., it is a root class such as Object).

          If present, this must be a class type, and not an array or primitive type.
      - id: interfaces_off
        type: u4
        doc: |
          offset from the start of the file to the list of interfaces, or 0 if there are none.

          This offset should be in the data section, and the data there should
          be in the format specified by "type_list" below. Each of the elements
          of the list must be a class type (not an array or primitive type),
          and there must not be any duplicates.
      - id: source_file_idx
        type: u4
        doc: |
          index into the string_ids list for the name of the file containing
          the original source for (at least most of) this class, or the
          special value NO_INDEX to represent a lack of this information.

          The debug_info_item of any given method may override this source file,
          but the expectation is that most classes will only come from one source file.
      - id: annotations_off
        type: u4
        doc: |
          offset from the start of the file to the annotations structure for
          this class, or 0 if there are no annotations on this class.

          This offset, if non-zero, should be in the data section, and the data
          there should be in the format specified by "annotations_directory_item"
          below,with all items referring to this class as the definer.
      - id: class_data_off
        type: u4
        doc: |
          offset from the start of the file to the associated class data for this
          item, or 0 if there is no class data for this class.

          (This may be the case, for example, if this class is a marker interface.)

          The offset, if non-zero, should be in the data section, and the data
          there should be in the format specified by "class_data_item" below,
          with all items referring to this class as the definer.
      - id: static_values_off
        type: u4
        doc: |
          offset from the start of the file to the list of initial values for
          static fields, or 0 if there are none (and all static fields are to be
          initialized with 0 or null).

          This offset should be in the data section, and the data there should
          be in the format specified by "encoded_array_item" below.

          The size of the array must be no larger than the number of static fields
          declared by this class, and the elements correspond to the static fields
          in the same order as declared in the corresponding field_list.

          The type of each array element must match the declared type of its
          corresponding field.

          If there are fewer elements in the array than there are static fields,
          then the leftover fields are initialized with a type-appropriate 0 or null.
    instances:
      type_name:
        value: _root.type_ids[class_idx].type_name
        -webide-parse-mode: eager
      class_data:
        pos: class_data_off
        type: class_data_item
        if: class_data_off != 0
      static_values:
        pos: static_values_off
        type: encoded_array_item
        if: static_values_off != 0
  encoded_array_item:
    seq:
      - id: value
        type: encoded_array
  annotation_element:
    seq:
      - id: name_idx
        type: vlq_base128_le
        doc: |
          element name, represented as an index into the string_ids section.

          The string must conform to the syntax for MemberName, defined above.
      - id: value
        type: encoded_value
        doc: |
          element value
  encoded_annotation:
    seq:
      - id: type_idx
        type: vlq_base128_le
        doc: |
          type of the annotation.

          This must be a class (not array or primitive) type.
      - id: size
        type: vlq_base128_le
        doc: |
          number of name-value mappings in this annotation
      - id: elements
        type: annotation_element
        repeat: expr
        repeat-expr: size.value
        doc: |
          elements of the annotation, represented directly in-line (not as offsets).

          Elements must be sorted in increasing order by string_id index.
  encoded_value:
    -webide-representation: "{value_type}: {value} (arg={value_arg})"
    seq:
      - id: value_arg
        type: b3
      - id: value_type
        type: b5
        enum: value_type_enum
      - id: value
        type:
          switch-on: value_type
          cases:
            # TODO: dynamic sizes
            value_type_enum::byte:          s1
            value_type_enum::short:         s2
            value_type_enum::char:          u2
            value_type_enum::int:           s4
            value_type_enum::long:          s8
            value_type_enum::float:         f4
            value_type_enum::double:        f8
            value_type_enum::method_type:   u4
            value_type_enum::method_handle: u4
            value_type_enum::string:        u4
            value_type_enum::type:          u4
            value_type_enum::field:         u4
            value_type_enum::method:        u4
            value_type_enum::enum:          u4
            value_type_enum::array:         encoded_array
            value_type_enum::annotation:    encoded_annotation
    enums:
      value_type_enum:
        0x00: byte
        0x02: short
        0x03: char
        0x04: int
        0x06: long
        0x10: float
        0x11: double
        0x15: method_type
        0x16: method_handle
        0x17: string
        0x18: type
        0x19: field
        0x1a: method
        0x1b: enum
        0x1c: array
        0x1d: annotation
        0x1e: "null"
        0x1f: boolean
  encoded_array:
    seq:
      - id: size
        type: vlq_base128_le
      - id: values
        type: encoded_value
        repeat: expr
        repeat-expr: size.value
  call_site_id_item:
    seq:
      - id: call_site_off
        type: u4
        doc: |
          offset from the start of the file to call site definition.

          The offset should be in the data section, and the data there should
          be in the format specified by "call_site_item" below.
  encoded_field:
    seq:
      - id: field_idx_diff
        type: vlq_base128_le
        doc: |
          index into the field_ids list for the identity of this field
          (includes the name and descriptor), represented as a difference
          from the index of previous element in the list.

          The index of the first element in a list is represented directly.
      - id: access_flags
        type: vlq_base128_le
        doc: |
          access flags for the field (public, final, etc.).

          See "access_flags Definitions" for details.
  encoded_method:
    seq:
      - id: method_idx_diff
        type: vlq_base128_le
        doc: |
          index into the method_ids list for the identity of this method
          (includes the name and descriptor), represented as a difference
          from the index of previous element in the list.

          The index of the first element in a list is represented directly.
      - id: access_flags
        type: vlq_base128_le
        doc: |
          access flags for the field (public, final, etc.).

          See "access_flags Definitions" for details.
      - id: ofs_code
        -orig-id: code_off
        type: vlq_base128_le
        doc: |
          offset from the start of the file to the code structure for this method,
          or 0 if this method is either abstract or native.

          The offset should be to a location in the data section.

          The format of the data is specified by "code_item" below.
    instances:
      code:
        pos: ofs_code.value
        type: code_item
        if: ofs_code.value != 0
  class_data_item:
    seq:
      - id: static_fields_size
        type: vlq_base128_le
        doc: |
          the number of static fields defined in this item
      - id: instance_fields_size
        type: vlq_base128_le
        doc: |
          the number of instance fields defined in this item
      - id: direct_methods_size
        type: vlq_base128_le
        doc: |
          the number of direct methods defined in this item
      - id: virtual_methods_size
        type: vlq_base128_le
        doc: |
          the number of virtual methods defined in this item
      - id: static_fields
        type: encoded_field
        repeat: expr
        repeat-expr: static_fields_size.value
        doc: |
          the defined static fields, represented as a sequence of encoded elements.

          The fields must be sorted by field_idx in increasing order.
      - id: instance_fields
        type: encoded_field
        repeat: expr
        repeat-expr: instance_fields_size.value
        doc: |
          the defined instance fields, represented as a sequence of encoded elements.

          The fields must be sorted by field_idx in increasing order.
      - id: direct_methods
        type: encoded_method
        repeat: expr
        repeat-expr: direct_methods_size.value
        doc: |
          the defined direct (any of static, private, or constructor) methods,
          represented as a sequence of encoded elements.

          The methods must be sorted by method_idx in increasing order.
      - id: virtual_methods
        type: encoded_method
        repeat: expr
        repeat-expr: virtual_methods_size.value
        doc: |
          the defined virtual (none of static, private, or constructor) methods,
          represented as a sequence of encoded elements.

          This list should not include inherited methods unless overridden by
          the class that this item represents.

          The methods must be sorted by method_idx in increasing order.

          The method_idx of a virtual method must not be the same as any direct method.
  code_item:
    seq:
      - id: num_registers
        -orig-id: registers_size
        type: u2
        doc: the number of registers used by this code
      - id: num_ins
        -orig-id: ins_size
        type: u2
        doc: the number of words of incoming arguments to the method that this code is for
      - id: num_outs
        -orig-id: outs_size
        type: u2
        doc: the number of words of outgoing argument space required by this code for method invocation
      - id: num_tries
        -orig-id: tries_size
        type: u2
        doc: |
          the number of try_items for this instance. If non-zero, then these appear as the
          tries array just after the insns in this instance.
      - id: ofs_debug_info
        -orig-id: debug_info_off
        type: u4
        doc: |
          offset from the start of the file to the debug info (line numbers +
          local variable info) sequence for this code, or 0 if there simply is
          no information. The offset, if non-zero, should be to a location in
          the data section. The format of the data is specified by
          "debug_info_item" below.
      - id: len_insns
        -orig-id: insns_size
        type: u4
        doc: |
          size of the instructions list, in 16-bit code units
      - id: insns
        size: len_insns * 2
        doc: |
          actual array of bytecode. The format of code in an insns array is
          specified by the companion document Dalvik bytecode. Note that
          though this is defined as an array of ushort, there are some internal
          structures that prefer four-byte alignment. Also, if this happens to
          be in an endian-swapped file, then the swapping is only done on
          individual ushorts and not on the larger internal structures.
      - id: padding
        size: 2
        if: num_tries != 0 and len_insns % 2 != 0
        doc: |
          two bytes of padding to make tries four-byte aligned. This element is
          only present if tries_size is non-zero and insns_size is odd.
      - id: tries
        type: try_item
        repeat: expr
        repeat-expr: num_tries
      - id: handlers
        type: encoded_catch_handler_list
        if: num_tries != 0
  encoded_catch_handler_list:
    seq:
      - id: num_entries
        -orig-id: size
        type: vlq_base128_le
        doc: size of this list, in entries
      - id: encoded_catch_handler
        type: encoded_catch_handler
        repeat: expr
        repeat-expr: num_entries.value_signed
        doc: |
          actual list of handler lists, represented directly
          (not as offsets), and concatenated sequentially
  encoded_catch_handler:
    seq:
      - id: num_catch_types
        -orig-id: size
        type: vlq_base128_le
        doc: |
          number of catch types in this list. If non-positive, then this is
          the negative of the number of catch types, and the catches are
          followed by a catch-all handler. For example: A size of 0 means that
          there is a catch-all but no explicitly typed catches. A size of 2
          means that there are two explicitly typed catches and no catch-all.
          And a size of -1 means that there is one typed catch along with
          a catch-all.
      - id: handlers
        type: encoded_type_addr_pair
        repeat: expr
        repeat-expr: '(num_catch_types.value_signed < 0 ? -num_catch_types.value_signed : num_catch_types.value_signed)'
        doc: |
          stream of abs(size) encoded items, one for each caught type, in
          the order that the types should be tested.
      - id: catch_all_addr
        type: vlq_base128_le
        if: num_catch_types.value < 1
        doc: |
          bytecode address of the catch-all handler. This element is only
          present if size is non-positive.
  encoded_type_addr_pair:
    seq:
      - id: type_idx
        type: vlq_base128_le
      - id: addr
        type: vlq_base128_le
  map_item:
    -webide-representation: "{type}: offs={offset}, size={size}"
    seq:
      - id: type
        type: u2
        enum: map_item_type
        doc: |
          type of the items; see table below
      - id: unused
        type: u2
        doc: |
          (unused)
      - id: size
        type: u4
        doc: |
          count of the number of items to be found at the indicated offset
      - id: offset
        type: u4
        doc: |
          offset from the start of the file to the items in question
    enums:
      map_item_type:
        0x0000: header_item
        0x0001: string_id_item
        0x0002: type_id_item
        0x0003: proto_id_item
        0x0004: field_id_item
        0x0005: method_id_item
        0x0006: class_def_item
        0x0007: call_site_id_item
        0x0008: method_handle_item
        0x1000: map_list
        0x1001: type_list
        0x1002: annotation_set_ref_list
        0x1003: annotation_set_item
        0x2000: class_data_item
        0x2001: code_item
        0x2002: string_data_item
        0x2003: debug_info_item
        0x2004: annotation_item
        0x2005: encoded_array_item
        0x2006: annotations_directory_item
  map_list:
    seq:
      - id: size
        type: u4
      - id: list
        type: map_item
        repeat: expr
        repeat-expr: size
  try_item:
    seq:
      - id: start_address
        type: u4
        doc: |
          start address of the block of code covered by this entry. The
          address is a count of 16-bit code units to the start of the
          first covered instruction.
      - id: num_instructions
        -orig-id: insn_count
        type: u2
        doc: |
          number of 16-bit code units covered by this entry. The last code
          unit covered (inclusive) is start_addr + insn_count - 1.
      - id: ofs_handler
        -orig-id: handler_off
        type: u2
        doc: |
          offset in bytes from the start of the associated
          encoded_catch_hander_list to the encoded_catch_handler for this
          entry. This must be an offset to the start of an
          encoded_catch_handler.
  type_item:
    seq:
      - id: type_idx
        type: u2
    instances:
      value:
        value: _root.type_ids[type_idx].type_name
  type_list:
    seq:
      - id: size
        type: u4
      - id: list
        type: type_item
        repeat: expr
        repeat-expr: size
enums:
  class_access_flags:
    0x0001: public     # public: visible everywhere
    0x0002: private    # * private: only visible to defining class
    0x0004: protected  # * protected: visible to package and subclasses
    0x0008: static     # * static: is not constructed with an outer this reference
    0x0010: final      # final: not subclassable
    0x0200: interface  # interface: multiply-implementable abstract class
    0x0400: abstract   # abstract: not directly instantiable
    0x1000: synthetic  # not directly defined in source code
    0x2000: annotation # declared as an annotation class
    0x4000: enum       # declared as an enumerated type
  opcodes:
    # The documentation on Google's website is not up to date, so also synced with
    # https://github.com/JesusFreke/smali/blob/master/dexlib2/src/main/java/org/jf/dexlib2/Opcode.java
    0x00:
      id: nop
      doc: Waste cycles.
    0x01:
      id: move
      doc: Move the contents of one non-object register to another.
    0x02:
      id: move_from16
      doc: Move the contents of one non-object register to another.
    0x03:
      id: move_16
      doc: Move the contents of one non-object register to another.
    0x04:
      id: move_wide
      doc: Move the contents of one register-pair to another.
    0x05:
      id: move_wide_from16
      doc: Move the contents of one register-pair to another.
    0x06:
      id: move_wide_16
      doc: Move the contents of one register-pair to another.
    0x07:
      id: move_object
      doc: Move the contents of one object-bearing register to another.
    0x08:
      id: move_object_from16
      doc: Move the contents of one object-bearing register to another.
    0x09:
      id: move_object_16
      doc: Move the contents of one object-bearing register to another.
    0x0a:
      id: move_result
      doc: |
        Move the single-word non-object result of the most recent invoke-kind
        into the indicated register. This must be done as the instruction
        immediately after an invoke-kind whose (single-word, non-object)
        result is not to be ignored; anywhere else is invalid.
    0x0b:
      id: move_result_wide
      doc: |
        Move the double-word result of the most recent invoke-kind into the
        indicated register pair. This must be done as the instruction
        immediately after an invoke-kind whose (double-word) result is not
        to be ignored; anywhere else is invalid.
    0x0c:
      id: move_result_object
      doc: |
        Move the object result of the most recent invoke-kind into the
        indicated register. This must be done as the instruction immediately
        after an invoke-kind or filled-new-array whose (object) result is not
        to be ignored; anywhere else is invalid.
    0x0d:
      id: move_exception
      doc: |
        Save a just-caught exception into the given register. This must be the
        first instruction of any exception handler whose caught exception is
        not to be ignored, and this instruction must only ever occur as the
        first instruction of an exception handler; anywhere else is invalid.
    0x0e:
      id: return_void
      doc: Return from a void method.
    0x0f:
      id: return
      doc: Return from a single-width (32-bit) non-object value-returning method.
    0x10:
      id: return_wide
      doc: Return from a double-width (64-bit) value-returning method.
    0x11:
      id: return_object
      doc: Return from an object-returning method.
    0x12:
      id: const_4
      doc: |
        Move the given literal value (sign-extended to 32 bits) into the
        specified register.
    0x13:
      id: const_16
      doc: |
        Move the given literal value (sign-extended to 32 bits) into the
        specified register.
    0x14:
      id: const
      doc: Move the given literal value into the specified register.
    0x15:
      id: const_high16
      doc: |
        Move the given literal value (right-zero-extended to 32 bits)
        into the specified register.
    0x16:
      id: const_wide_16
      doc: |
        Move the given literal value (sign-extended to 64 bits) into the
        specified register-pair.
    0x17:
      id: const_wide_32
      doc: |
        Move the given literal value (sign-extended to 64 bits) into the
        specified register-pair.
    0x18:
      id: const_wide
      doc: Move the given literal value into the specified register-pair.
    0x19:
      id: const_wide_high16
      doc: |
        Move the given literal value (right-zero-extended to 64 bits) into the
        specified register-pair.
    0x1a:
      id: const_string
      doc: |
        Move a reference to the string specified by the given index into the
        specified register.
    0x1b:
      id: const_string_jumbo
      doc: |
        Move a reference to the string specified by the given index into the
        specified register.
    0x1c:
      id: const_class
      doc: |
        Move a reference to the class specified by the given index into the
        specified register. In the case where the indicated type is primitive,
        this will store a reference to the primitive type's degenerate class.
    0x1d:
      id: monitor_enter
      doc: Acquire the monitor for the indicated object.
    0x1e:
      id: monitor_exit
      doc: Release the monitor for the indicated object.
    0x1f:
      id: check_cast
      doc: |
        Throw a ClassCastException if the reference in the given register
        cannot be cast to the indicated type.
    0x20:
      id: instance_of
      doc: |
        Store in the given destination register 1 if the indicated reference
        is an instance of the given type, or 0 if not.
    0x21:
      id: array_length
      doc: |
        Store in the given destination register the length of the indicated
        array, in entries
    0x22:
      id: new_instance
      doc: |
        Construct a new instance of the indicated type, storing a reference
        to it in the destination. The type must refer to a non-array class.
    0x23:
      id: new_array
      doc: |
        Construct a new array of the indicated type and size. The type must
        be an array type.
    0x24:
      id: filled_new_array
      doc: |
        Construct an array of the given type and size, filling it with the
        supplied contents. The type must be an array type. The array's contents
        must be single-word (that is, no arrays of long or double, but reference
        types are acceptable). The constructed instance is stored as a "result"
        in the same way that the method invocation instructions store their
        results, so the constructed instance must be moved to a register with
        an immediately subsequent move-result-object instruction (if it is to
        be used).
    0x25:
      id: filled_new_array_range
      doc: |
        Construct an array of the given type and size, filling it with the
        supplied contents. Clarifications and restrictions are the same as
        filled-new-array, described above.
    0x26:
      id: fill_array_data
      doc: |
        Fill the given array with the indicated data. The reference must be
        to an array of primitives, and the data table must match it in type
        and must contain no more elements than will fit in the array. That is,
        the array may be larger than the table, and if so, only the initial
        elements of the array are set, leaving the remainder alone.
    0x27:
      id: throw
      doc: Throw the indicated exception.
    0x28:
      id: goto
      doc: Unconditionally jump to the indicated instruction.
    0x29:
      id: goto_16
      doc: Unconditionally jump to the indicated instruction.
    0x2a:
      id: goto_32
      doc: Unconditionally jump to the indicated instruction.
    0x2b:
      id: packed_switch
      doc: |
        Jump to a new instruction based on the value in the given register,
        using a table of offsets corresponding to each value in a particular
        integral range, or fall through to the next instruction if there is
        no match.
    0x2c:
      id: sparse_switch
      doc: |
        Jump to a new instruction based on the value in the given register,
        using an ordered table of value-offset pairs, or fall through to the
        next instruction if there is no match.
    0x2d:
      id: cmpl_float
      doc: |
        Perform the indicated floating point or long comparison, setting a
        to 0 if b == c, 1 if b > c, or -1 if b < c.
    0x2e:
      id: cmpg_float
      doc: |
        Perform the indicated floating point or long comparison, setting a
        to 0 if b == c, 1 if b > c, or -1 if b < c.
    0x2f:
      id: cmpl_double
      doc: |
        Perform the indicated floating point or long comparison, setting a
        to 0 if b == c, 1 if b > c, or -1 if b < c.
    0x30:
      id: cmpg_double
      doc: |
        Perform the indicated floating point or long comparison, setting a
        to 0 if b == c, 1 if b > c, or -1 if b < c.
    0x31:
      id: cmpg_long
      doc: |
        Perform the indicated floating point or long comparison, setting a
        to 0 if b == c, 1 if b > c, or -1 if b < c.
    0x32:
      id: if_eq
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x33:
      id: if_ne
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x34:
      id: if_lt
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x35:
      id: if_ge
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x36:
      id: if_gt
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x37:
      id: if_le
      doc: |
        Branch to the given destination if the given two registers' values
        compare as specified.
    0x38:
      id: if_eqz
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    0x39:
      id: if_nez
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    0x3a:
      id: if_ltz
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    0x3b:
      id: if_gez
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    0x3c:
      id: if_gtz
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    0x3d:
      id: if_gtz
      doc: |
        Branch to the given destination if the given register's value compares
        with 0 as specified.
    # 0x3e - 0x43: unused
    0x44:
      id: aget
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x45:
      id: aget_wide
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x46:
      id: aget_object
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x47:
      id: aget_boolean
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x48:
      id: aget_byte
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x49:
      id: aget_char
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4a:
      id: aget_short
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4b:
      id: aput
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4c:
      id: aput_wide
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4d:
      id: aput_object
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4e:
      id: aput_boolean
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x4f:
      id: aput_byte
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x50:
      id: aput_char
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x51:
      id: aput_short
      doc: |
        Perform the identified array operation at the identified index of the
        given array, loading or storing into the value register.
    0x52:
      id: iget
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x53:
      id: iget_wide
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x54:
      id: iget_object
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x55:
      id: iget_boolean
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x56:
      id: iget_byte
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x57:
      id: iget_char
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x58:
      id: iget_short
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x59:
      id: iput
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5a:
      id: iput_wide
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5b:
      id: iput_object
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5c:
      id: iput_boolean
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5d:
      id: iput_byte
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5e:
      id: iput_char
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x5f:
      id: iput_short
      doc: |
        Perform the identified object instance field operation with the
        identified field, loading or storing into the value register.
    0x60:
      id: sget
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x61:
      id: sget_wide
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x62:
      id: sget_object
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x63:
      id: sget_boolean
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x64:
      id: sget_byte
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x65:
      id: sget_char
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x66:
      id: sget_short
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x67:
      id: sput
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x68:
      id: sput_wide
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x69:
      id: sput_object
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x6a:
      id: sput_boolean
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x6b:
      id: sput_byte
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x6c:
      id: sput_char
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x6d:
      id: sput_short
      doc: |
        Perform the identified object static field operation with the
        identified static field, loading or storing into the value register.
    0x6e:
      id: invoke_virtual
      doc: |
        Call the indicated method. The result (if any) may be stored with an
        appropriate move-result* variant as the immediately subsequent instruction.
    0x6f:
      id: invoke_super
      doc: |
        Call the indicated method. The result (if any) may be stored with an
        appropriate move-result* variant as the immediately subsequent instruction.
    0x70:
      id: invoke_direct
      doc: |
        Call the indicated method. The result (if any) may be stored with an
        appropriate move-result* variant as the immediately subsequent instruction.
    0x71:
      id: invoke_static
      doc: |
        Call the indicated method. The result (if any) may be stored with an
        appropriate move-result* variant as the immediately subsequent instruction.
    0x72:
      id: invoke_interface
      doc: |
        Call the indicated method. The result (if any) may be stored with an
        appropriate move-result* variant as the immediately subsequent instruction.
    # 0x73: unused , possibly return-void-no-barrier?
    0x74:
      id: invoke_virtual_range
      doc: |
        Call the indicated method. See first invoke-kind description above for
        details, caveats, and suggestions.
    0x75:
      id: invoke_super_range
      doc: |
        Call the indicated method. See first invoke-kind description above for
        details, caveats, and suggestions.
    0x76:
      id: invoke_direct_range
      doc: |
        Call the indicated method. See first invoke-kind description above for
        details, caveats, and suggestions.
    0x77:
      id: invoke_static_range
      doc: |
        Call the indicated method. See first invoke-kind description above for
        details, caveats, and suggestions.
    0x78:
      id: invoke_interface_range
      doc: |
        Call the indicated method. See first invoke-kind description above for
        details, caveats, and suggestions.
    # 0x79 - 0x7a : unused
    0x7b:
      id: neg_int
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x7c:
      id: not_int
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x7d:
      id: neg_long
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x7e:
      id: not_long
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x7f:
      id: neg_float
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x80:
      id: neg_double
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x81:
      id: int_to_long
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x82:
      id: int_to_float
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x83:
      id: int_to_double
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x84:
      id: long_to_int
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x85:
      id: long_to_float
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x86:
      id: long_to_double
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x87:
      id: float_to_int
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x88:
      id: float_to_long
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x89:
      id: float_to_double
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8a:
      id: double_to_int
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8b:
      id: double_to_long
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8c:
      id: double_to_float
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8d:
      id: int_to_byte
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8e:
      id: int_to_char
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x8f:
      id: int_to_short
      doc: |
        Perform the identified unary operation on the source register, storing
        the result in the destination register.
    0x90:
      id: add_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x91:
      id: sub_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x92:
      id: mul_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x93:
      id: div_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x94:
      id: rem_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x95:
      id: and_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x96:
      id: or_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x97:
      id: xor_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x98:
      id: shl_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x99:
      id: shr_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9a:
      id: ushr_int
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9b:
      id: add_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9c:
      id: sub_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9d:
      id: mul_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9e:
      id: div_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0x9f:
      id: rem_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa0:
      id: and_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa1:
      id: or_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa2:
      id: xor_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa3:
      id: shl_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa4:
      id: shr_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa5:
      id: ushr_long
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa6:
      id: add_float
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa7:
      id: sub_float
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa8:
      id: mul_float
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xa9:
      id: div_float
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xaa:
      id: rem_float
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xab:
      id: add_double
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xac:
      id: sub_double
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xad:
      id: mul_double
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xae:
      id: div_double
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xaf:
      id: rem_double
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the destination register.
    0xb0:
      id: add_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb1:
      id: sub_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb2:
      id: mul_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb3:
      id: div_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb4:
      id: rem_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb5:
      id: and_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb6:
      id: or_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb7:
      id: xor_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb8:
      id: shl_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xb9:
      id: shr_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xba:
      id: ushr_int_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xbb:
      id: add_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xbc:
      id: sub_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xbd:
      id: mul_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xbe:
      id: div_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xbf:
      id: rem_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc0:
      id: and_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc1:
      id: or_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc2:
      id: xor_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc3:
      id: shl_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc4:
      id: shr_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc5:
      id: ushr_long_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc6:
      id: add_float_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc7:
      id: sub_float_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc8:
      id: mul_float_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xc9:
      id: div_float_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xca:
      id: rem_float_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xcb:
      id: add_double_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xcc:
      id: sub_double_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xcd:
      id: mul_double_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xce:
      id: div_double_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xcf:
      id: rem_double_2addr
      doc: |
        Perform the identified binary operation on the two source registers,
        storing the result in the first source register.
    0xd0:
      id: add_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd1:
      id: rsub_int
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd2:
      id: mul_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd3:
      id: div_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd4:
      id: rem_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd5:
      id: and_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd6:
      id: or_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd7:
      id: xor_int_lit16
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result in
        the destination register.
    0xd8:
      id: add_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xd9:
      id: rsub_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xda:
      id: mul_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xdb:
      id: div_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xdc:
      id: rem_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xdd:
      id: and_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xde:
      id: or_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xdf:
      id: xor_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xe0:
      id: shl_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xe1:
      id: shr_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    0xe2:
      id: ushr_int_lit8
      doc: |
        Perform the indicated binary op on the indicated register (first
        argument) and literal value (second argument), storing the result
        in the destination register.
    # ec..f9 10x 	(unused) 	  	(unused)
    0xe3:
      id: iget_volatile
    0xe4:
      id: iput_volatile
    0xe5:
      id: sget_volatile
    0xe6:
      id: sput_volatile
    0xe7:
      id: iget_object_volatile
    0xe8:
      id: iget_wide_volatile
    0xe9:
      id: iput_wide_volatile
    0xea:
      id: sget_wide_volatile
    0xeb:
      id: sput_wide_volatile
    0xfa:
      id: invoke_polymorphic
      doc: |
         Invoke the indicated signature polymorphic method. The result (if any)
         may be stored with an appropriate move-result* variant as the
         immediately subsequent instruction.

         Present in Dex files from version 038 onwards.
    0xfb:
      id: invoke_polymorphic_range
      doc: |
        Invoke the indicated method handle. See the invoke-polymorphic
        description above for details.

        Present in Dex files from version 038 onwards.
    0xfc:
      id: invoke_custom
      doc: |
        Resolves and invokes the indicated call site. The result from the
        invocation (if any) may be stored with an appropriate move-result*
        variant as the immediately subsequent instruction.

        Present in Dex files from version 038 onwards.
    0xfd:
      id: invoke_custom_range
      doc: |
        Resolve and invoke a call site. See the invoke-custom description
        above for details.

        Present in Dex files from version 038 onwards.
    0xfe:
      id: const_method_handle
      doc: |
        Move a reference to the method handle specified by the given index
        into the specified register.

        Present in Dex files from version 039 onwards.
    0xff:
      id: const_method_type
      doc: |
        Move a reference to the method prototype specified by the given index
        into the specified register.

        Present in Dex files from version 039 onwards.
