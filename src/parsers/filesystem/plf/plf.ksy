meta:
  id: plf
  title: Parrot 
  license: CC0-1.0
  endian: le
  encoding: UTF-8
doc: |
  Parrot (drone manufacturer) has its own update files that have some sort
  of file system (PLF) with various types of partitions. Only some of these
  partitions are somewhat documented. It seems that there is also some
  inconsistency in the formats, but there is too little documentation.
  Not all data from this format might be unpacked in a sane way.

doc-ref:
  - http://embedded-software.blogspot.com/2010/12/plf-file-format.html
  - https://web.archive.org/web/20170109192314/http://thecyberrecce.net/2017/01/09/reversing-the-parrot-skycontroller-firmware/
  - https://github.com/Parrot-Developers/libARUpdater/blob/5b3667dd97c4ba0e38cb5f9a477773012c1e55d3/Sources/ARUPDATER_Plf.h
  - https://github.com/Parrot-Developers/libpuf/blob/master/src/libpuf_plf.h
  - https://github.com/scorp2kk/ardrone-tool
seq:
  - id: header
    type: header
  - id: padding
    size: header.len_header - header._sizeof
  - id: partitions
    type: partitions
    size: header.len_file - header.len_header
types:
  partitions:
    seq:
      - id: partitions
        type: partition
        repeat: eos
  header:
    seq:
      - id: magic
        contents: "PLF!"
      - id: header_version
        type: u4
      - id: len_header
        type: u4
      - id: len_entry_header
        type: u4
        valid: 20
      - id: file_type
        type: u4
        enum: file_types
      - id: entry_point
        type: u4
      - id: target_platform
        type: u4
      - id: target_application
        type: u4
      - id: hardware_compatibility
        type: u4
      - id: version
        type: version
      - id: language_zone
        type: u4
      - id: len_file
        type: u4
  version:
    seq:
      - id: major_version
        type: u4
      - id: minor_version
        type: u4
      - id: bugfix_version
        type: u4
  partition:
    seq:
      - id: section_type
        type: u4
        enum: section_types
      - id: len_section
        type: u4
      - id: crc32
        type: u4
      - id: load_address
        type: u4
      - id: uncompressed_size
        type: u4
      - id: data
        size: len_section
      - id: padding
        size: (-len_section % 4)
        doc: additional padding to keep partitions 4 byte aligned
enums:
  section_types:
    0x0: unknown_0
    0x1: unknown_1
    0x2: unknown_2
    0x3: boot_loader
    0x4: unknown_4
    0x5: directory_names
    0x6: unknown_6
    0x7: boot_configuration
    0x8: unknown_8
    0x9: file_system_data
    0xa: unknown_10
    0xb: partition_table
    0xc: installer
  file_types:
    0: unknown
    1: executable
    2: archive
