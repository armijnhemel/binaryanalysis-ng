meta:
  id: ico
  title: Microsoft Windows icon file
  file-extension: ico
  ks-version: 0.9
  endian: le
  license: CC0-1.0
doc: |
  Microsoft Windows uses specific file format to store applications
  icons - ICO. This is a container that contains one or more image
  files (effectively, DIB parts of BMP files or full PNG files are
  contained inside).
doc-ref:
  - https://msdn.microsoft.com/en-us/library/ms997538.aspx
  - https://en.wikipedia.org/wiki/ICO_(file_format)
seq:
  - id: magic
    contents: [0, 0, 1, 0]
  - id: num_images
    -orig-id: idCount
    type: u2
    valid:
      min: 1
    doc: Number of images contained in this file
  - id: images
    -orig-id: idEntries
    type: icon_dir_entry
    repeat: expr
    repeat-expr: num_images
types:
  icon_dir_entry:
    -orig-id: ICONDIRENTRY
    seq:
      - id: width
        -orig-id: bWidth
        type: u1
        doc: Width of image, px. Value 0 means image width is 256 pixels.
      - id: height
        -orig-id: bHeight
        type: u1
        doc: Height of image, px. Value 0 means image height is 256 pixels.
      - id: num_colors
        -orig-id: bColorCount
        type: u1
        doc: |
          Number of colors in palette of the image or 0 if image has
          no palette (i.e. RGB, RGBA, etc)
      - id: reserved
        -orig-id: bReserved
        type: u1
        valid:
          any-of: [0, 255]
        doc: |
          According to Wikipedia: "Although Microsoft's technical documentation
          states that this value must be zero, the icon encoder built into .NET
          (System.Drawing.Icon.Save) sets this value to 255. It appears that
          the operating system ignores this value altogether."
      - id: num_planes
        -orig-id: wPlanes
        type: u2
        doc: Number of color planes
      - id: bpp
        -orig-id: wBitCount
        type: u2
        doc: Bits per pixel in the image
      - id: len_img
        -orig-id: dwBytesInRes
        type: u4
        valid:
          min: 1
        doc: Size of the image data
      - id: ofs_img
        -orig-id: dwImageOffset
        type: u4
        doc: Absolute offset of the image data start in the file
    instances:
      img:
        pos: ofs_img
        size: len_img
        doc: |
          Raw image data. Use `is_png` to determine whether this is an
          embedded PNG file (true) or a DIB bitmap (false) and call a
          relevant parser, if needed to parse image data further.
      png_header:
        pos: ofs_img
        size: 8
        doc: |
          Pre-reads first 8 bytes of the image to determine if it's an
          embedded PNG file.
      is_png:
        value: png_header == [137, 80, 78, 71, 13, 10, 26, 10]
        doc: True if this image is in PNG format.
