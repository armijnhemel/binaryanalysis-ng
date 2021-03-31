meta:
  id: mng
  title: MNG (Multiple-image Network Graphics) file
  file-extension: mng
  xref:
    justsolve: MNG
    mime: video/x-mng
    pronom: fmt/528
    wikidata: Q904680
  license: CC0-1.0
  ks-version: 0.9
  endian: be
doc-ref: http://www.libpng.org/pub/mng/spec/
seq:
  - id: magic
    contents: [138, 77, 78, 71, 13, 10, 26, 10]
  - id: mhdr_len
    type: u4
    valid: 28
  - id: mhdr_type
    contents: "MHDR"
  - id: mhdr
    type: mhdr_chunk
  - id: mhdr_crc
    size: 4
  - id: mng_frames
    type: mng_frame
    #enum: mng_frame_type
    repeat: expr
    repeat-expr: eos
  - id: mend
    type: mend_chunk
types:
  mng_frame:
    # A MNG datastream describes a sequence of zero or more single frames,
    # each of which can be composed of zero or more embedded images or
    # directives to show previously defined images. 
    seq:
      # A stream of PNGs
      - id: pngs
        type: png_stream
      # OR a frame
  mhdr_chunk:
    seq:
      - id: width
        type: u4
      - id: height
        type: u4
      - id: ticks
        type: u4
        doc: Ticks per second
      - id: layer_count
        type: u4
      - id: frame_count
        type: u4
      - id: play_time
        type: u4
      - id: simplicity_profile
        type: u4
  mend_chunk:
    seq:
      - id: len
        type: u4
      - id: type
        contents: "MEND"
      - id: crc
        size: 4
  png_stream:
    seq:
      # https://www.w3.org/TR/PNG/#11IHDR
      # Always appears first, stores values referenced by other chunks
      - id: ihdr_len
        type: u4
        valid: 13
      - id: ihdr_type
        contents: "IHDR"
      - id: ihdr
        type: ihdr_chunk
      - id: ihdr_crc
        size: 4
        # The rest of the chunks
      - id: chunks
        type: chunk
        repeat: until
        repeat-until: _.type == "IEND"
  chunk:
    seq:
      - id: len
        type: u4
      - id: type
        type: str
        size: 4
        encoding: UTF-8
      - id: body
        size: len
        type:
          switch-on: type
          cases:
            # Critical chunks
            #'"IHDR"': ihdr_chunk
            '"PLTE"': plte_chunk
            # IDAT = raw
            # IEND = empty, thus raw

            # Ancillary chunks
            '"cHRM"': chrm_chunk
            '"gAMA"': gama_chunk
            # iCCP
            # sBIT
            '"sRGB"': srgb_chunk
            '"bKGD"': bkgd_chunk
            # hIST
            # tRNS
            '"pHYs"': phys_chunk
            # sPLT
            '"tIME"': time_chunk
            '"iTXt"': international_text_chunk
            '"tEXt"': text_chunk
            '"zTXt"': compressed_text_chunk
      - id: crc
        size: 4
  ihdr_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11IHDR
    seq:
      - id: width
        type: u4
      - id: height
        type: u4
      - id: bit_depth
        type: u1
      - id: color_type
        type: u1
        enum: color_type
      - id: compression_method
        type: u1
      - id: filter_method
        type: u1
      - id: interlace_method
        type: u1
  plte_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11PLTE
    seq:
      - id: entries
        type: rgb
        repeat: eos
  rgb:
    seq:
      - id: r
        type: u1
      - id: g
        type: u1
      - id: b
        type: u1
  chrm_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11cHRM
    seq:
      - id: white_point
        type: point
      - id: red
        type: point
      - id: green
        type: point
      - id: blue
        type: point
  point:
    seq:
      - id: x_int
        type: u4
      - id: y_int
        type: u4
    instances:
      x:
        value: x_int / 100000.0
      y:
        value: y_int / 100000.0
  gama_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11gAMA
    seq:
      - id: gamma_int
        type: u4
    instances:
      gamma_ratio:
        value: 100000.0 / gamma_int
  srgb_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11sRGB
    seq:
      - id: render_intent
        type: u1
        enum: intent
    enums:
      intent:
        0: perceptual
        1: relative_colorimetric
        2: saturation
        3: absolute_colorimetric
  bkgd_chunk:
    doc: |
      Background chunk stores default background color to display this
      image against. Contents depend on `color_type` of the image.
    doc-ref: https://www.w3.org/TR/PNG/#11bKGD
    seq:
      - id: bkgd
        type:
          switch-on: _parent.ihdr.color_type
          cases:
            color_type::greyscale: bkgd_greyscale
            color_type::greyscale_alpha: bkgd_greyscale
            color_type::truecolor: bkgd_truecolor
            color_type::truecolor_alpha: bkgd_truecolor
            color_type::indexed: bkgd_indexed
  bkgd_greyscale:
    doc: Background chunk for greyscale images.
    seq:
      - id: value
        type: u2
  bkgd_truecolor:
    doc: Background chunk for truecolor images.
    seq:
      - id: red
        type: u2
      - id: green
        type: u2
      - id: blue
        type: u2
  bkgd_indexed:
    doc: Background chunk for images with indexed palette.
    seq:
      - id: palette_index
        type: u1
  phys_chunk:
    doc: |
      "Physical size" chunk stores data that allows to translate
      logical pixels into physical units (meters, etc) and vice-versa.
    doc-ref: https://www.w3.org/TR/PNG/#11pHYs
    seq:
      - id: pixels_per_unit_x
        type: u4
        doc: |
          Number of pixels per physical unit (typically, 1 meter) by X
          axis.
      - id: pixels_per_unit_y
        type: u4
        doc: |
          Number of pixels per physical unit (typically, 1 meter) by Y
          axis.
      - id: unit
        type: u1
        enum: phys_unit
  time_chunk:
    doc: |
      Time chunk stores time stamp of last modification of this image,
      up to 1 second precision in UTC timezone.
    doc-ref: https://www.w3.org/TR/PNG/#11tIME
    seq:
      - id: year
        type: u2
      - id: month
        type: u1
      - id: day
        type: u1
      - id: hour
        type: u1
      - id: minute
        type: u1
      - id: second
        type: u1
  international_text_chunk:
    doc: |
      International text chunk effectively allows to store key-value string pairs in
      PNG container. Both "key" (keyword) and "value" (text) parts are
      given in pre-defined subset of iso8859-1 without control
      characters.
    doc-ref: https://www.w3.org/TR/PNG/#11iTXt
    seq:
      - id: keyword
        type: strz
        encoding: UTF-8
        doc: Indicates purpose of the following text data.
      - id: compression_flag
        type: u1
        doc: |
          0 = text is uncompressed, 1 = text is compressed with a
          method specified in `compression_method`.
      - id: compression_method
        type: u1
        enum: compression_methods
      - id: language_tag
        type: strz
        encoding: ASCII
        doc: |
          Human language used in `translated_keyword` and `text`
          attributes - should be a language code conforming to ISO
          646.IRV:1991.
      - id: translated_keyword
        type: strz
        encoding: UTF-8
        doc: |
          Keyword translated into language specified in
          `language_tag`. Line breaks are not allowed.
      - id: text
        type: str
        encoding: UTF-8
        size-eos: true
        doc: |
          Text contents ("value" of this key-value pair), written in
          language specified in `language_tag`. Linke breaks are
          allowed.
  text_chunk:
    doc: |
      Text chunk effectively allows to store key-value string pairs in
      PNG container. Both "key" (keyword) and "value" (text) parts are
      given in pre-defined subset of iso8859-1 without control
      characters.
    doc-ref: https://www.w3.org/TR/PNG/#11tEXt
    seq:
      - id: keyword
        type: strz
        encoding: iso8859-1
        doc: Indicates purpose of the following text data.
      - id: text
        type: str
        size-eos: true
        encoding: iso8859-1
  compressed_text_chunk:
    doc: |
      Compressed text chunk effectively allows to store key-value
      string pairs in PNG container, compressing "value" part (which
      can be quite lengthy) with zlib compression.
    doc-ref: https://www.w3.org/TR/PNG/#11zTXt
    seq:
      - id: keyword
        type: strz
        encoding: UTF-8
        doc: Indicates purpose of the following text data.
      - id: compression_method
        type: u1
        enum: compression_methods
      - id: text_datastream
        process: zlib
        size-eos: true
enums:
  color_type:
    0: greyscale
    2: truecolor
    3: indexed
    4: greyscale_alpha
    6: truecolor_alpha
  phys_unit:
    0: unknown
    1: meter
  compression_methods:
    0: zlib
  dispose_op_values:
    0:
      id: none
      doc: |
        No disposal is done on this frame before rendering the next;
        the contents of the output buffer are left as is.
      doc-ref: https://wiki.mozilla.org/APNG_Specification#.60fcTL.60:_The_Frame_Control_Chunk
    1:
      id: background
      doc: |
        The frame's region of the output buffer is to be cleared to
        fully transparent black before rendering the next frame.
      doc-ref: https://wiki.mozilla.org/APNG_Specification#.60fcTL.60:_The_Frame_Control_Chunk
    2:
      id: previous
      doc: |
        The frame's region of the output buffer is to be reverted
        to the previous contents before rendering the next frame.
      doc-ref: https://wiki.mozilla.org/APNG_Specification#.60fcTL.60:_The_Frame_Control_Chunk
  blend_op_values:
    0:
      id: source
      doc: |
        All color components of the frame, including alpha,
        overwrite the current contents of the frame's output buffer region.
    1:
      id: over
      doc: |
        The frame is composited onto the output buffer based on its alpha
