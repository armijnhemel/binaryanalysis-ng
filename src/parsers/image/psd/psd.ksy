meta:
  id: psd
  title: Photoshop
  file-extension: psd
  license: CC0-1.0
  ks-version: 0.9
  endian: be
doc: |
  Simple grammar for Photoshop PSD that has enough functionality
  to replace a handwritten parser in BANG.

seq:
  - id: header
    type: header
  - id: color_mode_data
    type: color_mode_data
  - id: image_resources
    type: image_resources
  - id: layer_and_mask_information
    type: layer_and_mask_information
  - id: image_data
    type: image_data
types:
  header:
    seq:
      - id: magic
        contents: "8BPS"
      - id: version
        type: u2
        valid: 1
      - id: reserved
        contents: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
      - id: num_channels
        type: u2
        valid:
          min: 1
          max: 56
      - id: height
        type: u4
        valid:
          min: 1
          max: 30000
      - id: width
        type: u4
        valid:
          min: 1
          max: 30000
      - id: depth
        type: u2
        valid:
          any-of: [1, 8, 16, 32]
      - id: color_mode
        type: u2
        enum: color_mode
        valid:
          any-of:
            - color_mode::bitmap
            - color_mode::grayscale
            - color_mode::indexed
            - color_mode::rgb
            - color_mode::cmyk
            - color_mode::multichannel
            - color_mode::duotone
            - color_mode::lab
  color_mode_data:
    seq:
      - id: len_color_mode
        type: u4
      - id: color_mode
        size: len_color_mode
  image_resources:
    seq:
      - id: len_resources
        type: u4
      - id: resources
        size: len_resources
  layer_and_mask_information:
    seq:
      - id: len_layer_and_mask_information
        type: u4
      - id: layer_and_mask_information
        size: len_layer_and_mask_information
  image_data:
    seq:
      - id: compression
        type: u2
        enum: compression
        # only support raw and rle data for now
        valid:
          any-of:
            - compression::raw
            - compression::rle
      - id: data
        type:
          switch-on: compression
          cases:
            compression::raw: raw_data
            compression::rle: rle_data
  raw_data:
    seq:
      - id: data
        size: _root.header.height * _root.header.width * _root.header.num_channels
  rle_data:
    seq:
      - id: byte_counts
        type: u2
        repeat: expr
        repeat-expr: _root.header.height * _root.header.num_channels
      - id: rle
        size: byte_counts[_index]
        repeat: expr
        repeat-expr: _root.header.height * _root.header.num_channels
enums:
  color_mode:
    0: bitmap
    1: grayscale
    2: indexed
    3: rgb
    4: cmyk
    7: multichannel
    8: duotone
    9: lab
  compression:
    0: raw
    1: rle
    2: zip_without_prediction
    3: zip_with_prediction
