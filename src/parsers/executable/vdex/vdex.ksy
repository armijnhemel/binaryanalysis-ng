meta:
  id: vdex
  title: VDex
  file-extension: vdex
  license: CC0-1.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
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
        '"019"': header_019
        #'"027"': header_027
types:
  header_019:
    seq:
      - id: dex_section_version
        type: strz
        size: 4
      - id: num_dex_files
        type: u4
      - id: verifier_deps_size
        type: u4
    doc-ref: https://android.googlesource.com/platform/art/+/c17b7d80652765750fa7f2baf236061014b23f93/runtime/vdex_file.h
  #header_027:
    #seq:
      #- id: num_sections
        #type: u4
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
