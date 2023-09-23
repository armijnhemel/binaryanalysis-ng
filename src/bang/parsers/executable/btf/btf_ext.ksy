meta:
  id: btf_ext
  title: BTF.ext
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://docs.kernel.org/bpf/btf.html
seq:
  - id: header
    type: header
  - id: func_info_section
    size: header.rest_of_header.len_func_info_section
    type: func_info
  - id: line_info_section
    size: header.rest_of_header.len_line_info_section
    type: func_info
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
          - id: ofs_func_info_section
            type: u4
          - id: len_func_info_section
            type: u4
          - id: ofs_line_info_section
            type: u4
          - id: len_line_info_section
            type: u4
          - id: ofs_core_relo
            type: u4
            if: _parent.len_header >= 32
          - id: len_core_relo
            type: u4
            if: _parent.len_header >= 32
  func_info:
    seq:
      - id: len_info_rec
        type: u4
      - id: btf_ext_info_secs
        type: btf_ext_info_sec
        repeat: eos
  line_info:
    seq:
      - id: len_info_rec
        type: u4
      - id: btf_ext_info_secs
        type: btf_ext_info_sec
        repeat: eos
  btf_ext_info_sec:
    seq:
      - id: ofs_section_name
        type: u4
      - id: num_info
        type: u4
        valid:
          min: 1
      - id: data
        size: num_info * _parent.len_info_rec
