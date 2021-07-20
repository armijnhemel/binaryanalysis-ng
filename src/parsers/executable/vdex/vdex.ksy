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
  version 019: Android 9 (verified: walleye-ppr1.180610.009-factory-4149f7e5.zip )
  version 021: Android 10 & 11
doc-ref: https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h
seq:
  - id: magic
    contents: "vdex"
  - id: version
    type: strz
    size: 4
  - id: dex_header
    type:
      switch-on: version
      cases:
        '"006"': header_006_010
        '"010"': header_006_010
        '"019"': header_019_021(version)
        '"021"': header_019_021(version)
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
  header_021:
    seq:
     - id: dex_section_version
       type: strz
       size: 4
     - id: num_dex
       type: u4
     - id: len_verifier_deps
       type: u4
     - id: dex_checksums
       type: u4
       repeat: expr
       repeat-expr: num_dex
     - id: dex_section_header
       type: dex_section_header_019_021
       if: dex_section_version != '000'
  section_header:
    seq:
      - id: section_kind
        type: u4
        enum: vdex_section
      - id: ofs_section
        type: u4
      - id: len_section
        type: u4
enums:
  vdex_section:
    0: checksum
    1: dex_file
    2: verifier_deps
    3: type_lookup_table
    4: number_of_sections
