meta:
  id: webp
  title: WebP
  license: CC0-1.0
  endian: le
  encoding: UTF-8
doc-ref:
  - https://developers.google.com/speed/webp/docs/riff_container
seq:
  - id: magic
    contents: "RIFF"
  - id: len_data
    type: u4
  - id: webp
    contents: "WEBP"
  - id: payload
    size: len_data - webp._sizeof
    type: chunks
types:
  chunks:
    seq:
      - id: chunks
        type: chunk
        repeat: eos
  chunk:
    seq:
      - id: name
        type: u4
        enum: chunk_names
        valid:
          any-of:
            - chunk_names::alph
            - chunk_names::anim
            - chunk_names::anmf
            - chunk_names::exif
            - chunk_names::frgm
            - chunk_names::iccp
            - chunk_names::vp8l
            - chunk_names::vp8
            - chunk_names::vp8x
            - chunk_names::xmp
      - id: len_data
        type: u4
      - id: data
        size: len_data
        type:
          switch-on: name
          cases:
            chunk_names::alph: alph
            chunk_names::anim: anim
            chunk_names::anmf: anmf
            chunk_names::vp8l: vp8l
            chunk_names::vp8x: vp8x
            chunk_names::xmp: xmp
      - id: padding
        size: 1
        if: len_data % 2 != 0
  vp8l:
    # https://developers.google.com/speed/webp/docs/webp_lossless_bitstream_specification
    seq:
      - id: signature
        type: u1
        valid: 0x2f
      - id: data
        size-eos: true
  vp8x:
    seq:
      - id: reserved1
        type: b2
      - id: icc_profile
        type: b1
      - id: alpha
        type: b1
      - id: exif
        type: b1
      - id: xmp
        type: b1
      - id: animation
        type: b1
      - id: reserved2
        type: b1
      - id: reserved3
        type: b24
        valid: 0
      - id: canvas_width
        type: b24le
      - id: canvas_height
        type: b24le
    instances:
      height:
        value: canvas_height + 1
      width:
        value: canvas_width + 1
  alph:
    seq:
      - id: reserved
        type: b2
        valid: 0
      - id: preprocessing
        type: b2
        enum: preprocessing
      - id: filtering
        type: b2
        enum: filter_methods
      - id: compression
        type: b2
        enum: compression
  anim:
    seq:
      - id: background
        type: u4
      - id: loop_count
        type: u2
  anmf:
    seq:
      - id: frame_x
        type: b24le
      - id: frame_y
        type: b24le
      - id: frame_width
        type: b24le
      - id: frame_height
        type: b24le
      - id: duration
        type: b24le
      - id: reserved
        type: b6
      - id: blending_method
        type: b1
      - id: disposal_method
        type: b1
      - id: data
        size-eos: true
    instances:
      height:
        value: frame_height + 1
      width:
        value: frame_width + 1
  xmp:
    seq:
      - id: data
        size-eos: true
        type: str
        encoding: UTF-8
enums:
  chunk_names:
    0x48504c41: alph
    0x4d494e41: anim
    0x464d4e41: anmf
    0x46495845: exif
    0x4d475246: frgm
    0x50434349: iccp
    0x4c385056: vp8l
    0x20385056: vp8
    0x58385056: vp8x
    0x20504d58: xmp
  filter_methods:
    0: no_filter
    1: horizontal
    2: vertical
    3: gradient
  compression:
    0: no_compression
    1: webp_lossless
  preprocessing:
    0: no_preprocessing
    1: level_reduction
