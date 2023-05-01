meta:
  id: imgdiff
  title: imgdiff
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc-ref:
  - https://android.googlesource.com/platform/bootable/recovery/+/d1ba38f7c96e74901779089fea6d09b0c7c2521d/applypatch/imgdiff.cpp#53
seq:
  - id: magic
    contents: 'IMGDIFF'
  - id: version
    type: u1
    valid:
      any-of: [0x31, 0x32]
  - id: num_chunks
    type: u4
  - id: chunks
    type: chunk
    repeat: expr
    repeat-expr: num_chunks
types:
  chunk:
    seq:
      - id: chunk_type
        type: u4
        enum: chunk_types
      - id: chunk_body
        type:
          switch-on: chunk_type
          cases:
            chunk_types::normal: chunk_normal
            chunk_types::gzip: chunk_gzip
            chunk_types::deflate: chunk_deflate
            chunk_types::raw: chunk_raw
  chunk_normal:
    seq:
      - id: ofs_source
        type: u8
      - id: len_source
        type: u8
      - id: ofs_bsdiff_patch
        type: u8
    instances:
      bsdiff:
        pos: ofs_bsdiff_patch
        type: bsdiff40
  chunk_gzip:
    seq:
      - id: ofs_source
        type: u8
      - id: len_source
        type: u8
      - id: ofs_bsdiff_patch
        type: u8
      - id: len_expanded_source
        type: u8
      - id: len_expanded_target
        type: u8
      - id: gzip_info
        type: gzip_info
      - id: len_gzip_header
        type: u4
      - id: gzip_header
        size: len_gzip_header
      - id: gzip_footer
        size: 8
    instances:
      bsdiff:
        pos: ofs_bsdiff_patch
        type: bsdiff40
  chunk_deflate:
    seq:
      - id: ofs_source
        type: u8
      - id: len_source
        type: u8
      - id: ofs_bsdiff_patch
        type: u8
      - id: len_expanded_source
        type: u8
      - id: len_expanded_target
        type: u8
      - id: gzip_info
        type: gzip_info
    instances:
      bsdiff:
        pos: ofs_bsdiff_patch
        type: bsdiff40
  chunk_raw:
    seq:
      - id: len_target
        type: u4
      - id: data
        size: len_target
  gzip_info:
    seq:
      - id: level
        type: u4
      - id: method
        type: u4
      - id: window_bits
        type: u4
      - id: mem_level
        type: u4
      - id: strategy
        type: u4
  bsdiff40:
    seq:
      - id: magic
        contents: 'BSDIFF40'
      - id: len_control_block
        type: u8
      - id: len_diff_block
        type: u8
      - id: len_new_file
        type: u8
      - id: control_block
        size: len_control_block
      - id: diff_block
        size: len_diff_block
      #- id: extra_block
        #size: ???
enums:
  chunk_types:
    0: normal
    1: gzip
    2: deflate
    3: raw
