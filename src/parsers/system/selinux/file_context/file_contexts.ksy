meta:
  id: file_contexts
  title: SELinux file_contexts.bin
  file-extension: bin
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://github.com/SELinuxProject/selinux/blob/b550c0e/libselinux/utils/sefcontext_compile.c#L68
seq:
  - id: magic
    size: 4
    contents: [0x8a, 0xff, 0x7c, 0xf9]
    # SELINUX_MAGIC_COMPILED_FCONTEXT
  - id: version
    type: u4
  - id: len_pcre_version
    type: u4
  - id: pcre_version
    type: strz
    size: len_pcre_version
  - id: num_stems
    type: u4
  - id: stems
    type: stem
    repeat: expr
    repeat-expr: num_stems
  - id: num_regexes
    type: u4
  - id: regexes
    type: regex
    repeat: expr
    repeat-expr: num_regexes
types:
  stem:
    seq:
      - id: len_stem
        type: u4
        # EXCLUDING NUL
      - id: stem
        type: strz
        size: len_stem + 1
        # INCLUDING NUL
  regex:
    seq:
      - id: len_context
        type: u4
      - id: raw_context
        type: strz
        size: len_context
      - id: len_regex_str
        type: u4
      - id: regex_str
        type: strz
        size: len_regex_str
      - id: mode_bits
        type: u4
      - id: stem_id
        type: s4
      - id: spec_meta_chars
        type: u4
      - id: spec_prefix_len
        type: u4
      - id: len_pcre_regex_data
        type: u4
      - id: pcre_regex_data
        size: len_pcre_regex_data
      - id: len_pcre_regex_study_data
        type: u4
      - id: pcre_regex_study_data
        size: len_pcre_regex_study_data
