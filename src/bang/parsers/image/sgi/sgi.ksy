meta:
  id: sgi
  title: SGI Image File Format
  file-extension:
    - sgi
    - rgb
    - rgba
    - bw
    - int
    - inta
  xref:
    justsolve: SGI_(image_file_format)
    mime: image/sgi
    pronom: x-fmt/140
    wikidata: Q7514956
  license: CC0-1.0
  ks-version: 0.9
  encoding: ASCII
  endian: be
doc-ref: https://media.xiph.org/svt/SGIIMAGESPEC
seq:
  - id: header
    type: header
    size: 512
  - id: body
    type:
      switch-on: header.storage_format
      cases:
        storage_format::verbatim: verbatim
        storage_format::rle: rle
types:
  header:
    seq:
      - id: magic
        contents: [0x01, 0xda]
      - id: storage_format
        type: u1
        enum: storage_format
      - id: bytes_per_pixel
        type: u1
      - id: num_dimensions
        type: u2
        valid:
          any-of: [1, 2, 3]
      - id: xsize
        type: u2
      - id: ysize
        type: u2
      - id: zsize
        type: u2
      - id: min_pix
        type: u4
      - id: max_pix
        type: u4
      - id: ignored1
        type: padding(4)
      - id: name
        type: strz
        size: 80
      - id: colormap
        type: u4
        enum: colormap
        valid:
          any-of:
            - colormap::normal
            - colormap::dithered
            - colormap::screen
            - colormap::colormap
      - id: ignored
        type: padding(404)
  padding:
    params:
      - id: num_padding
        type: u4
    seq:
      - id: padding_bytes
        type: padding_byte
        repeat: expr
        repeat-expr: num_padding
  padding_byte:
    seq:
      - id: padding_byte
        contents: [0x00]
  verbatim:
    seq:
      - id: data
        size: _root.header.xsize * _root.header.ysize * _root.header.zsize * _root.header.bytes_per_pixel
  rle:
    seq:
      - id: start_table_entries
        type: u4
        repeat: expr
        repeat-expr: _root.header.ysize * _root.header.zsize
      - id: length_table_entries
        type: u4
        repeat: expr
        repeat-expr: _root.header.ysize * _root.header.zsize
    instances:
      scanlines:
        type: scanline(_index)
        repeat: expr
        repeat-expr: _root.header.ysize * _root.header.zsize
  scanline:
    params:
      - id: i
        type: u4
    instances:
      data:
        pos: _parent.start_table_entries[i]
        size: _parent.length_table_entries[i]
        io: _root._io
enums:
  storage_format:
    0: verbatim
    1: rle
  colormap:
    0: normal
    1: dithered
    2: screen
    3: colormap
