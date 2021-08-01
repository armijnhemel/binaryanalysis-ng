meta:
  id: lxl_openwrt
  title: Luxul firmware header format (OpenWrt)
  file-extension: lxl
  license: MIT
  endian: le
  encoding: UTF-8
doc: |
  Luxul is a device manufacturer which has devices onto which OpenWrt
  can be installed. The format described here only applies to the OpenWrt
  builds, not to the firmware downloads from Luxul, which seem to have
  a different header.

  Only the header is described in this field.

  Test files: <https://openwrt.org/toh/hwdata/luxul/luxul_xbr-4500>
doc-ref: https://raw.githubusercontent.com/openwrt/openwrt/9aa6569a/tools/firmware-utils/src/lxlfw.c
seq:
  - id: magic
    contents: "LXL#"
  - id: version
    type: u4
    valid:
      any-of: [0, 1, 2]
  - id: len_header
    -orig-id: hdr_len
    type: u4
  - id: flags
    type: u4
    if: version > 0
  - id: board
    type: strz
    size: 16
    if: version > 0
  - id: release
    size: 16
    if: version > 1
