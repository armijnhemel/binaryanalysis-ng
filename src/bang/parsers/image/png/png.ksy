meta:
  id: png
  title: PNG (Portable Network Graphics) file
  file-extension:
    - png
    - apng
  xref:
    forensicswiki: Portable_Network_Graphics_(PNG)
    iso: 15948:2004
    justsolve:
      - PNG
      - APNG
    loc: fdd000153
    mime:
      - image/png
      - image/apng
      - image/vnd.mozilla.apng
    pronom:
      - fmt/11 # PNG 1.0
      - fmt/12 # PNG 1.1
      - fmt/13 # PNG 1.2
      - fmt/935 # APNG
    rfc: 2083
    wikidata:
      - Q178051 # PNG
      - Q433224 # APNG
  license: CC0-1.0
  ks-version: 0.9
  endian: be
doc: |
  Test files for APNG can be found at the following locations:

    * <https://philip.html5.org/tests/apng/tests.html>
    * <http://littlesvr.ca/apng/>
seq:
  # https://www.w3.org/TR/PNG/#5PNG-file-signature
  - id: magic
    contents: [137, 80, 78, 71, 13, 10, 26, 10]
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
    repeat-until: _.type == "IEND" or _io.eof
types:
  chunk:
    -webide-representation: "{type}"
    seq:
      - id: len
        type: u4
      - id: type
        type: str
        size: 4
        encoding: UTF-8
        valid:
          expr: type != "\0\0\0\0"
      - id: body
        size: len
        type:
          switch-on: type
          cases:
            # Critical chunks
            # '"IHDR"': ihdr_chunk
            '"PLTE"': plte_chunk
            # IDAT = raw
            # IEND = empty, thus raw

            # Ancillary chunks
            '"cHRM"': chrm_chunk
            '"cICP"': cicp_chunk
            '"cLLi"': clli_chunk
            '"gAMA"': gama_chunk
            # iCCP
            '"mDCv"': mdcv_chunk
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

            # animated PNG chunks
            '"acTL"': animation_control_chunk
            '"fcTL"': frame_control_chunk
            '"fdAT"': frame_data_chunk

            # Adobe Fireworks chunks
            '"mkBS"': adobe_fireworks_chunk
            '"mkTS"': adobe_fireworks_chunk
            '"prVW"': adobe_fireworks_chunk

            # evernote/skitch chunks
            '"skRf"': evernote_skrf_chunk

            # pngattach: https://nullprogram.com/blog/2021/12/31/
            '"atCh"': atch_chunk

            # https://exiftool.org/TagNames/XMP.html#SEAL
            # https://github.com/hackerfactor/SEAL/blob/master/FORMATS.md#png
            # seAl
      - id: crc
        size: 4
  ihdr_chunk:
    doc-ref: https://www.w3.org/TR/PNG/#11IHDR
    seq:
      - id: width
        type: u4
        valid:
          min: 1
      - id: height
        type: u4
        valid:
          min: 1
      - id: bit_depth
        type: u1
        valid:
          any-of: [1, 2, 4, 8, 16]
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
  cicp_chunk:
    doc-ref: https://w3c.github.io/PNG-spec/#cICP-chunk
    seq:
      - id: colour_primaries
        type: u1
      - id: transfer_function
        type: u1
      - id: matrix_coefficients
        type: u1
      - id: video_full_range_flag
        type: u1
  clli_chunk:
    doc-ref: https://w3c.github.io/PNG-spec/#cLLi-chunk
    seq:
      - id: maximum_content_light_level
        type: u4
      - id: maximum_frame_average_light_level
        type: u4
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
  mdcv_chunk:
    doc-ref: https://w3c.github.io/PNG-spec/#mDCv-chunk
    seq:
      - id: colour_primaries
        size: 12
      - id: white_point_chromaticity
        type: u4
      - id: maximum_luminance
        type: u4
      - id: minimum_luminance
        type: u4
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
          switch-on: _root.ihdr.color_type
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
        valid:
          any-of: [0, 1]
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
        type:
          switch-on: compression_flag
          cases:
            0: international_text
            1: international_text_compressed
        size-eos: true
        doc: |
          Text contents ("value" of this key-value pair), written in
          language specified in `language_tag`. Line breaks are
          allowed.
  international_text:
    seq:
      - id: text
        type: str
        encoding: UTF-8
        size-eos: true
        doc: |
          Text contents ("value" of this key-value pair), written in
          language specified in `language_tag`. Line breaks are
          allowed.
  international_text_compressed:
    seq:
      - id: text
        size-eos: true
        process: zlib
        doc: |
          Text contents ("value" of this key-value pair), written in
          language specified in `language_tag`. Line breaks are
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
  animation_control_chunk:
    doc-ref: https://wiki.mozilla.org/APNG_Specification#.60acTL.60:_The_Animation_Control_Chunk
    seq:
      - id: num_frames
        type: u4
        doc: Number of frames, must be equal to the number of `frame_control_chunk`s
      - id: num_plays
        type: u4
        doc: Number of times to loop, 0 indicates infinite looping.
  frame_control_chunk:
    doc-ref: https://wiki.mozilla.org/APNG_Specification#.60fcTL.60:_The_Frame_Control_Chunk
    seq:
      - id: sequence_number
        type: u4
        doc: Sequence number of the animation chunk
      - id: width
        type: u4
        valid:
          min: 1
          max: _root.ihdr.width
        doc: Width of the following frame
      - id: height
        type: u4
        valid:
          min: 1
          max: _root.ihdr.height
        doc: Height of the following frame
      - id: x_offset
        type: u4
        valid:
          max: _root.ihdr.width - width
        doc: X position at which to render the following frame
      - id: y_offset
        type: u4
        valid:
          max: _root.ihdr.height - height
        doc: Y position at which to render the following frame
      - id: delay_num
        type: u2
        doc: Frame delay fraction numerator
      - id: delay_den
        type: u2
        doc: Frame delay fraction denominator
      - id: dispose_op
        type: u1
        enum: dispose_op_values
        doc: Type of frame area disposal to be done after rendering this frame
      - id: blend_op
        type: u1
        enum: blend_op_values
        doc: Type of frame area rendering for this frame
    instances:
      delay:
        value: 'delay_num / (delay_den == 0 ? 100.0 : delay_den)'
        doc: Time to display this frame, in seconds
  frame_data_chunk:
    doc-ref: https://wiki.mozilla.org/APNG_Specification#.60fdAT.60:_The_Frame_Data_Chunk
    seq:
      - id: sequence_number
        type: u4
        doc: |
          Sequence number of the animation chunk. The fcTL and fdAT chunks
          have a 4 byte sequence number. Both chunk types share the sequence.
          The first fcTL chunk must contain sequence number 0, and the sequence
          numbers in the remaining fcTL and fdAT chunks must be in order, with
          no gaps or duplicates.
      - id: frame_data
        size-eos: true
        doc: |
          Frame data for the frame. At least one fdAT chunk is required for
          each frame. The compressed datastream is the concatenation of the
          contents of the data fields of all the fdAT chunks within a frame.
  adobe_fireworks_chunk:
    doc-ref: https://stackoverflow.com/questions/4242402/the-fireworks-png-format-any-insight-any-libs/51683285#51683285
    seq:
      - id: preview_data
        process: zlib
        size-eos: true
  evernote_skrf_chunk:
    seq:
      - id: uuid
        size: 16
      - id: data
        size-eos: true
  atch_chunk:
    seq:
      - id: name
        type: strz
        encoding: utf-8
      - id: compression
        type: u1
        enum: compression_attach_methods
        valid:
          any-of:
            - compression_attach_methods::no_compression
            - compression_attach_methods::zlib
      - id: data
        size-eos: true
    enums:
      compression_attach_methods:
        0: no_compression
        1: zlib
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
