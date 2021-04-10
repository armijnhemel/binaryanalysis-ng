meta:
  id: bsdiff
  title: bsdiff format
  xref:
    pronom: fmt/439
  license: CC-1.0
  ks-version: 0.9
  endian: le
doc-ref:
  - http://www.daemonology.net/bsdiff/
  - https://github.com/cperciva/bsdiff/blob/d6c34c/bspatch/bspatch.c
seq:
  - id: magic
    contents: "BSDIFF40"
  - id: len_x
    -orig-id: x
    type: u8
  - id: len_y
    -orig-id: y
    type: u8
  - id: len_new_file
    type: u8
  - id: control_block
    size: len_x
  - id: diff_block
    size: len_y
