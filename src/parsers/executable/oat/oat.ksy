meta:
  id: oat
  title: oat
  file-extension: oat
  license: Apache-2.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
doc: |
  <https://github.com/JesusFreke/smali/blob/master/dexlib2/OatVersions.txt>
doc-ref: https://android.googlesource.com/platform/art/+/master/runtime/oat.h
seq:
  - id: magic
    contents: "oat\n"
  - id: version
    type: strz
    size: 4
  - id: dex_header
    type:
      switch-on: version
      cases:
        '"131"': header_137
        '"137"': header_137
types:
  header_137:
    seq:
      - id: adler32_checksum
        type: u4
      - id: instruction_set
        type: u4
      - id: instruction_set_features_bitmap
        type: u4
      - id: num_dex_file
        -orig-id: dex_file_count_
        type: u4
      - id: ofs_oat_dex_files
        -orig-id: oat_dex_files_offset_
        type: u4
      - id: ofs_executable
        -orig-id: executable_offset_
        type: u4
      - id: ofs_interpreter_to_interpreter_bridge
        -orig-id: interpreter_to_interpreter_bridge_offset_
        type: u4
      - id: ofs_interpreter_to_compiled_code_bridge
        -orig-id: interpreter_to_compiled_code_bridge_offset_
        type: u4
      - id: ofs_jni_dlsym_lookup
        -orig-id: jni_dlsym_lookup_offset_
        type: u4
      - id: ofs_quick_generic_jni_trampoline
        -orig-id: quick_generic_jni_trampoline_offset_
        type: u4
      - id: ofs_quick_imt_conflict_trampoline
        -orig-id: quick_imt_conflict_trampoline_offset_
        type: u4
      - id: ofs_quick_resolution_trampoline
        -orig-id: quick_resolution_trampoline_offset_
        type: u4
      - id: ofs_quick_to_interpreter_bridge
        -orig-id: quick_to_interpreter_bridge_offset_
        type: u4
