meta:
  id: android_vendor_boot
  title: Android Vendor Boot image
  license: Apache-2.0
  endian: le
doc-ref: https://android.googlesource.com/platform/system/tools/mkbootimg/+/b4b04c2a965d9b3ce1ebf0442fc8047fe103d4e6/include/bootimg/bootimg.h
seq:
  - id: header
    type: header
  - id: padding1
    size: (- _io.pos) % header.page_size
  - id: vendor_ramdisk
    size: header.len_vendor_ramdisk
  - id: padding2
    size: (- _io.pos) % header.page_size
  - id: dtb
    size: header.len_dtb
  - id: padding3
    size: (- _io.pos) % header.page_size

types:
  header:
    seq:
      - id: magic
        contents: "VNDRBOOT"
      - id: version
        -orig-id: header_version
        type: u4
        valid:
          any-of: [3]
        # only support version 3, as version 4 is too new
      - id: page_size
        -orig-id: page_size
        type: u4
        doc: flash page size we assume
      - id: kernel_address
        -orig-id: kernel_addr
        type: u4
        doc: physical load addr
      - id: ramdisk_address
        -orig-id: ramdisk_addr
        type: u4
        doc: physical load addr
      - id: len_vendor_ramdisk
        -orig-id: vendor_ramdisk_size
        type: u4
        doc: size in bytes
      - id: commandline
        -orig-id: cmdline
        type: strz
        encoding: ASCII
        size: 2048
        doc: asciiz kernel commandline
      - id: tags_address
        -orig-id: tags_addr
        type: u4
        doc: physical addr for kernel tags (if required)
      - id: name
        -orig-id: cmdline
        type: strz
        encoding: ASCII
        size: 16
        doc: asciiz product name
      - id: len_header
        -orig-id: header_size
        type: u4
      - id: len_dtb
        -orig-id: dtb_size
        type: u4
        doc: size in bytes for DTB image
      - id: dtb_address
        -orig-id: dtb_addr
        type: u8
        doc: physical load address for DTB image
