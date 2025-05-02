meta:
  id: allwinner_img
  title: Allwinner image format
  file-extension: img
  tags:
    - archive
    - android
  license: CC0-1.0
  endian: le
doc: |
  Format of boot files found on certain Android devices based on Allwinner chipsets.

doc-ref: https://github.com/Ithamar/awutils/blob/5d6284e/imagewty.h
seq:
  - id: img_header
    type: header
    size: 1024
  - id: file_headers
    type: file_header
    repeat: expr
    repeat-expr: img_header.num_files
types:
  header:
     seq:
        - id: magic
          contents: "IMAGEWTY"
        - id: header_version
          type: u4
        - id: len_header
          -orig-id: header_size
          type: u4
        - id: ram_base
          type: u4
        - id: format_version
          -orig-id: version
          valid: 0x100234
          type: u4
        - id: len_image
          -orig-id: image_size
          type: u4
        - id: len_image_header
          -orig-id: image_header_size
          type: u4
        - id: unknown
          type: u4
          if: header_version == 0x300
        - id: usb_pid
          -orig-id: pid
          type: u4
        - id: usb_vid
          -orig-id: vid
          type: u4
        - id: hardware_id
          type: u4
        - id: firmware_id
          type: u4
        - id: val1
          type: u4
          valid: 1
        - id: val1024_1
          type: u4
          valid: 1024
        - id: num_files
          type: u4
        - id: val1024_2
          type: u4
          valid: 1024
        - id: val0_1
          type: u4
          valid: 0
        - id: val0_2
          type: u4
          valid: 0
        - id: val0_3
          type: u4
          valid: 0
        - id: val0_4
          type: u4
          valid: 0
  file_header:
    seq:
      - id: common
        type: file_header_common
      - id: file_header_data
        type:
          switch-on: _root.img_header.header_version
          cases:
            0x100: file_header_v1
            0x300: file_header_v3
        size: common.len_header_total - common._sizeof
  file_header_common:
    seq:
      - id: len_filename
        -orig-id: filename_len
        type: u4
      - id: len_header_total
        -orig-id: total_header_size
        type: u4
      - id: maintype
        type: str
        encoding: ASCII
        size: 8
      - id: subtype
        type: str
        encoding: ASCII
        size: 16
  file_header_v1:
    seq:
      - id: unknown_1
        type: u4
      - id: stored_length
        type: u4
      - id: original_length
        type: u4
      - id: offset
        type: u4
      - id: unknown_2
        type: u4
      - id: name
        -orig-id: filename
        type: strz
        encoding: ASCII
        size: 256
  file_header_v3:
    seq:
      - id: unknown_0
        type: u4
        valid: 0
      - id: name
        -orig-id: filename
        type: strz
        encoding: ASCII
        size: 256
      - id: stored_length
        type: u4
      - id: pad1
        size: 4
      - id: original_length
        type: u4
      - id: pad2
        size: 4
      - id: offset
        type: u4
