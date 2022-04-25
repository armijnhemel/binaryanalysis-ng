meta:
  id: android_img_lk
  title: Android Boot Image with LK support
  file-extension: img
  tags:
    - archive
    - android
  license: CC0-1.0
  endian: le
doc: |
  A variant from (probably) Qualcomm with a slightly different file format.

  Test file: lineage-14.1-20180620-nightly-FP2-signed.zip
doc-ref:
  - https://github.com/M1cha/android_bootable_bootloader_lk/blob/condor/app/aboot/bootimg.h
seq:
  - id: header
    type: header
instances:
  header_version:
    pos: 40
    type: u4
    valid:
      min: 40
types:
  header:
    seq:
      - id: magic
        contents: ANDROID!
      - id: kernel
        type: load
      - id: ramdisk
        type: load
      - id: second
        type: load
      - id: tags_load
        type: u4
      - id: page_size
        type: u4
      - id: dt_size
        type: u4
      - id: unused
        type: u4
      - id: name
        type: strz
        size: 16
        encoding: ASCII
      - id: cmdline
        type: strz
        size: 512
        encoding: ASCII

    instances:
      base:
        value: kernel.addr - 0x00008000
        doc: base loading address
      kernel_offset:
        value: kernel.addr - base
        doc: kernel offset from base
      ramdisk_offset:
        value: 'ramdisk.addr > 0 ? ramdisk.addr - base : 0'
        doc: ramdisk offset from base
      second_offset:
        value: 'second.addr > 0 ? second.addr - base : 0'
        doc: 2nd bootloader offset from base
      tags_offset:
        value: tags_load - base
        doc: tags offset from base
      kernel_img:
        pos: page_size
        size: kernel.size
      ramdisk_img:
        pos: ((page_size + kernel.size + page_size - 1) / page_size) * page_size
        size: ramdisk.size
        if: ramdisk.size > 0
      second_img:
        pos: ((page_size + kernel.size + ramdisk.size + page_size - 1) / page_size) * page_size
        size: second.size
        if: second.size > 0
      dtb_pos:
        value: ((page_size + kernel.size + ramdisk.size + second.size + page_size - 1) / page_size) * page_size
      dtb:
        pos: dtb_pos
        size: dt_size
  load:
    seq:
      - id: size
        type: u4
      - id: addr
        type: u4
