meta:
  id: android_imgdiff
  title: Android imgdiff
  license: CC-1.0
  ks-version: 0.9
  endian: le
doc-ref:
  - https://android.googlesource.com/platform/bootable/recovery/+/refs/tags/android-platform-11.0.0_r5/applypatch/imgdiff.cpp
  - https://android.googlesource.com/platform/bootable/recovery/+/refs/tags/android-platform-11.0.0_r5/applypatch/include/applypatch/imgdiff.h
seq:
  - id: magic
    contents: "IMGDIFF"
  - id: version
    type: u1
    valid: 0x32
    doc: Only support version 2
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
  chunk_deflate:
    seq:
      - id: source_start
        type: u8
      - id: source_len
        type: u8
      - id: ofs_bsdiff
        type: u8
      - id: source_expanded_length
        type: u8
      - id: target_expected_length
        type: u8
      - id: gzip_level
        type: u4
      - id: gzip_method
        type: u4
      - id: gzip_windowbits
        type: u4
      - id: gzip_memlevel
        type: u4
      - id: gzip_strategy
        type: u4
  chunk_gzip:
    seq:
      - id: source_start
        type: u8
      - id: source_len
        type: u8
      - id: ofs_bsdiff
        type: u8
      - id: source_expanded_length
        type: u8
      - id: target_expected_length
        type: u8
      - id: gzip_level
        type: u4
      - id: gzip_method
        type: u4
      - id: gzip_windowbits
        type: u4
      - id: gzip_memlevel
        type: u4
      - id: gzip_strategy
        type: u4
      - id: len_gzip_header
        type: u4
      - id: gzip_header
        size: len_gzip_header
      - id: gzip_footer
        type: u8
  chunk_normal:
    seq:
      - id: source_start
        type: u8
      - id: source_len
        type: u8
      - id: ofs_bsdiff
        type: u8
  chunk_raw:
    seq:
      - id: len_target
        type: u4
      - id: target
        size: len_target
enums:
  chunk_types:
    0: normal
    1: gzip
    2: deflate
    3: raw
