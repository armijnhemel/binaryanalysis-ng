meta:
  id: sunraster
  title: SUN raster
  license: CC0-1.0
  ks-version: 0.9
  endian: be
doc-ref:
  - https://www.fileformat.info/format/sunraster/egff.htm
  - https://www.fileformat.info/format/sunraster/spec/6191a773bc0046f18d42e77ca16c3a8c/view.htm
  - https://www.fileformat.info/format/sunraster/spec/598a59c4fac64c52897585d390d86360/view.htm
seq:
  - id: magic
    contents: [0x59, 0xa6, 0x6a, 0x95]
  - id: width
    type: u4
  - id: height
    type: u4
  - id: depth
    type: u4
  - id: len_image_data
    type: u4
  - id: bitmap_type
    type: u4
    enum: bitmap_types
    valid:
      any-of:
        - bitmap_types::old
        - bitmap_types::standard
        - bitmap_types::byte_encoded
        - bitmap_types::rgb
        - bitmap_types::tiff
        - bitmap_types::iff
        - bitmap_types::experimental
  - id: color_map_type
    type: u4
    valid:
      any-of: [0, 1, 2]
  - id: len_color_map
    -orig-id: ColorMapLength
    type: u4

enums:
  bitmap_types:
    0: old
    1: standard
    2: byte_encoded
    3: rgb
    4: tiff
    5: iff
    0xffff: experimental
