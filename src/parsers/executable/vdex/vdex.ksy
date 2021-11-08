meta:
  id: vdex
  title: VDex
  file-extension: vdex
  license: Apache-2.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
doc: |
  Verified Dex

  version 006: Android 8 (verified: walleye-opd1.170816.010-factory-63083164.zip )
  version 010: Android 8.1 (verified: walleye-opm1.171019.011-factory-f74dd4fd.zip )
  version 019: Android 9 (verified: walleye-ppr1.180610.009-factory-4149f7e5.zip )
  version 021: Android 10 & 11
  version 027: Android 12 (verified: raven-sd1a.210817.015.a4-factory-bd6cb030.zip )
doc-ref: https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h
seq:
  - id: magic
    contents: "vdex"
  - id: version
    type: strz
    size: 4
    valid:
      any-of: ['"006"', '"010"', '"019"', '"021"', '"027"'] # update whenever there is a new Android
  - id: dex_header
    type:
      switch-on: version
      cases:
        '"006"': header_006_010
        '"010"': header_006_010
        '"019"': header_019_021(version)
        '"021"': header_019_021(version)
        '"027"': header_027
types:
  header_006_010:
    seq:
      - id: num_dex
        type: u4
      - id: len_dex
        type: u4
      - id: len_verifier_deps
        -orig-id: verifier_deps_size_
        type: u4
      - id: len_quickening_info
        -orig-id: quickening_info_size_
        type: u4
      - id: location_checksum
        type: u4
      - id: dex_files
        # type: dex_files
        size: len_dex
      - id: verifier_deps
        size: len_verifier_deps
      - id: quickening_info
        size: len_quickening_info
  header_019_021:
    params:
      - id: version
        type: str
    seq:
     - id: dex_section_version
       type: strz
       size: 4
     - id: num_dex
       type: u4
     - id: len_verifier_deps
       type: u4
     - id: len_bootclasspath_checksum
       type: u4
       if: version == '021'
     - id: len_classloader_context
       type: u4
       if: version == '021'
     - id: dex_checksums
       type: u4
       repeat: expr
       repeat-expr: num_dex
     - id: dex_section_header
       type: dex_section_header_019_021
       if: dex_section_version != '000'
     - id: verifier_deps
       size: len_verifier_deps
     - id: quickening_info
       size: dex_section_header.len_quickening_info
       if: dex_section_version != '000'
  dex_section_header_019_021:
    seq:
      - id: len_dex
        type: u4
      - id: len_dex_shared_data
        type: u4
      - id: len_quickening_info
        type: u4
      - id: quicken_and_dex
        size: len_dex + len_dex_shared_data
  header_027:
    seq:
      - id: num_sections
        type: u4
        valid: 4
        doc: kNumberOfSections = 4
      - id: sections
        type: section_027
        repeat: expr
        repeat-expr: num_sections
  section_027:
    seq:
      - id: section_kind
        type: u4
        enum: vdex_section
      - id: ofs_section
        type: u4
      - id: len_section
        type: u4
    instances:
      section:
        pos: ofs_section
        size: len_section
        io: _root._io
        if: ofs_section != 0
  cdex_header:
    seq:
      - id: magic
        contents: "cdex"
      - id: version
        type: strz
        size: 4
      - id: checksum
        type: u4
      - id: sha1
        size: 20
      - id: len_file
        type: u4
      - id: len_header
        type: u4
      - id: endian_tag
        type: u4
      - id: len_link
        type: u4
      - id: ofs_link
        type: u4
      - id: ofs_map
        type: u4
      - id: len_string_ids
        type: u4
      - id: ofs_string_ids
        type: u4
      - id: len_type_ids
        type: u4
      - id: ofs_type_ids
        type: u4
      - id: len_proto_ids
        type: u4
      - id: ofs_proto_ids
        type: u4
      - id: len_field_ids
        type: u4
      - id: ofs_field_ids
        type: u4
      - id: len_method_ids
        type: u4
      - id: ofs_method_ids
        type: u4
      - id: len_class_defs
        type: u4
      - id: ofs_class_defs
        type: u4
      - id: len_data
        type: u4
      - id: ofs_data
        type: u4
      - id: feature_flags
        type: u4
      - id: ofs_debug_info_offsets
        type: u4
      - id: ofs_debug_info_offsets_table
        type: u4
      - id: debug_info_base
        type: u4
      - id: owned_data_begin
        type: u4
      - id: owned_data_end
        type: u4
enums:
  vdex_section:
    0: checksum
    1: dex_file
    2: verifier_deps
    3: type_lookup_table
    4: number_of_sections
