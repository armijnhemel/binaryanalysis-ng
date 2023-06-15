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
    type: vendor_ramdisk
  - id: padding2
    size: (- _io.pos) % header.page_size
  - id: dtb
    size: header.len_dtb
  - id: padding3
    size: (- _io.pos) % header.page_size
  - id: vendor_ramdisk_table
    size: header.v4header.len_vendor_ramdisk_table
    type: ramdisk_table(header.v4header.num_vendor_ramdisk_table_entry, header.v4header.len_vendor_ramdisk_table_entry)
    if: header.version == 4
  - id: padding4
    size: (- _io.pos) % header.page_size
    if: header.version == 4
  - id: bootconfig
    size: header.v4header.len_bootconfig
    if: header.version == 4
  - id: padding5
    size: (- _io.pos) % header.page_size
    if: header.version == 4
types:
  vendor_ramdisk:
    seq:
      - id: data
        size-eos: true
  header:
    seq:
      - id: magic
        contents: "VNDRBOOT"
      - id: version
        -orig-id: header_version
        type: u4
        valid:
          any-of: [3, 4]
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
      - id: v4header
        type: v4header
        if: version == 4
  v4header:
    seq:
      - id: len_vendor_ramdisk_table
        -orig-id: vendor_ramdisk_table_size
        type: u4
        doc: size in bytes for the vendor ramdisk table
      - id: num_vendor_ramdisk_table_entry
        -orig-id: vendor_ramdisk_table_entry_num
        type: u4
        doc: number of entries in the vendor ramdisk tabl
      - id: len_vendor_ramdisk_table_entry
        -orig-id: vendor_ramdisk_table_entry_size
        type: u4
        doc: size in bytes for a vendor ramdisk table entry
      - id: len_bootconfig
        -orig-id: bootconfig_size
        type: u4
        doc: size in bytes for the bootconfig section
  ramdisk_table_entry_v4:
    seq:
      - id: len_ramdisk
        -orig-id: ramdisk_size
        type: u4
        valid:
          max: _root.header.len_vendor_ramdisk
        doc: size in bytes for the ramdisk image
      - id: ofs_ramdisk
        -orig-id: ramdisk_offset
        type: u4
        doc: offset to the ramdisk image in vendor ramdisk section
        valid:
          max: _root.header.len_vendor_ramdisk - len_ramdisk
      - id: ramdisk_type
        type: u4
        enum: ramdisk_types
        doc: type of the ramdisk
      - id: name
        type: strz
        size: 32
        encoding: ASCII
        doc: asciiz ramdisk name
      - id: board_ids
        type: u4
        repeat: expr
        repeat-expr: 16
        doc: |
          Hardware identifiers describing the board, soc or platform which this
          ramdisk is intended to be loaded on.
    instances:
      ramdisk:
        pos: ofs_ramdisk
        size: len_ramdisk
        io: _root.vendor_ramdisk._io
  ramdisk_table:
    params:
      - id: num_entries
        type: u4
      - id: len_entry
        type: u4
    seq:
      - id: entries
        type: ramdisk_table_entry_v4
        size: len_entry
        repeat: expr
        repeat-expr: num_entries
enums:
  ramdisk_types:
    0: no_type
    1: platform
    2: recovery
    3: dlkm
