meta:
  id: android_imgdata
  title: LG Android imgdata
  license: CC-1.0
  encoding: UTF-8
  endian: le
doc-ref:
  https://github.com/NVISOsecurity/nexus_5_bootloader_unpacker/blob/master/imgdata_tool.c
  https://gist.github.com/shinyquagsire23/ba0f6209592d50fb8e4166620228aaa5
seq:
  - id: header
    type: header
  - id: images
    type: image
    repeat: expr
    repeat-expr: header.num_files
types:
  header:
    seq:
      - id: magic
        contents: "IMGDATA!"
      - id: unknown
        type: u4
      - id: num_files
        type: u4
      - id: padding
        size: 8
  image:
    seq:
      - id: name
        size: 16
        type: strz
      - id: image_width
        -orig-id: imgwidth
        type: u4
      - id: image_height
        -orig-id: imgheight
        type: u4
      - id: screen_x_position
        -orig-id: scrxpos
        type: u4
      - id: screen_y_position
        -orig-id: scrypos
        type: u4
      - id: ofs_image
        -orig-id: offset
        type: u4
      - id: len_image
        -orig-id: size
        type: u4
    instances:
      image_body:
        pos: ofs_image
        io: _root._io
        size: len_image
