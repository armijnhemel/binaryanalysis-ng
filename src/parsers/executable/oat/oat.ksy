meta:
  id: oat
  title: oat
  file-extension: oat
  license: Apache-2.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
doc: |
  The OAT format is an optimized format for Dalvik DEX code. OAT files are
  typically distributed as ELF files, with the OAT and DEX code spanning
  various ELF sections.

  Google frequently updates the OAT format, but not every version is in use
  in real products.

  <https://github.com/JesusFreke/smali/blob/master/dexlib2/OatVersions.txt>
doc-ref: https://android.googlesource.com/platform/art/+/master/runtime/oat.h
seq:
  - id: magic
    contents: "oat\n"
  - id: version
    type: strz
    size: 4
  - id: oat_header
    type:
      switch-on: version
      cases:
        '"079"': header_079
        '"131"': header_131
        '"137"': header_131
        '"138"': header_131
types:
  header_079:
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
      - id: image_patch_delta
        type: u4
      - id: ofs_image_file_oat_checksum
        -orig-id: image_file_location_oat_checksum_
        type: u4
      - id: ofs_image_file_location_oat_data
        -orig-id: image_file_location_oat_data_begin_
        type: u4
      - id: len_key_value_store
        -orig-id: key_value_store_size_
        type: u4
      - id: key_value_store
        type: key_value_store
        size: len_key_value_store
  header_131:
    # same as header_079 but with a few more fields
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
      - id: image_patch_delta
        type: u4
      - id: ofs_image_file_oat_checksum
        -orig-id: image_file_location_oat_checksum_
        type: u4
      - id: ofs_image_file_location_oat_data
        -orig-id: image_file_location_oat_data_begin_
        type: u4
      - id: len_key_value_store
        -orig-id: key_value_store_size_
        type: u4
      - id: key_value_store
        type: key_value_store
        size: len_key_value_store
  key_value_store:
    seq:
      - id: key_values
        type: key_value
        repeat: eos
  key_value:
    seq:
      - id: key
        type: strz
      - id: value
        type: strz
