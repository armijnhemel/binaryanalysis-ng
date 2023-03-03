meta:
  id: gdkp
  title: Android logo.bin for MediaTek devices
  license: LGPL-1.0-or-later
  encoding: UTF-8
  endian: be
doc-ref:
  - https://gitlab.gnome.org/GNOME/gdk-pixbuf/-/blob/2.42.2/gdk-pixbuf/gdk-pixdata.h
seq:
  - id: header
    type: header
    size: 24
  - id: pixel_data
    size: header.len_pixel_data - header._sizeof
types:
  header:
    seq:
      - id: magic
        contents: 'GdkP'
      - id: len_pixel_data
        type: u4
      - id: pixdata_type
        type: u4
      - id: rowstride
        type: u4
      - id: width
        type: u4
      - id: height
        type: u4
