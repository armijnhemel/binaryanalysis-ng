meta:
  id: pif
  title: Portable Image Format
  file-extension: pif
  license: LGPL-2.1
  ks-version: 0.9
  endian: le
doc-ref: https://github.com/gfcwfzkm/PIF-Image-Format/blob/cc256d5/Specification/PIF%20Format%20Specification.pdf
seq:
  - id: header
    type: header
  - id: information_header
    type: information_header
  - id: color_table
    size: information_header.len_color_table
  - id: data
    size: information_header.len_image
types:
  header:
    seq:
      - id: magic
        contents: ["PIF", 0x00]
      - id: len_file
        type: u4
      - id: ofs_pixel_array
        type: u4
  information_header:
    seq:
      - id: image_type
        type: u2
        enum: image_type
      - id: bits_per_pixel
        type: u2
      - id: width
        type: u2
      - id: height
        type: u2
      - id: len_image
        type: u4
      - id: len_color_table
        type: u2
      - id: compressed
        type: u2
        valid:
          any-of: [0, 0x7dde]
    instances:
      is_compressed:
        value: compressed == 0x7dde
enums:
  image_type:
    0x433c: rgb888
    0xe5c5: rgb565
    0x1e53: rgb332
    0xb895: rgb16c
    0x7daa: black_white
    0x4952: indexed_24
    0x4947: indexed_16
    0x4942: indexed_8
