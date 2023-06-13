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
        type:
          switch-on: section_type
          cases:
            section_types::section11: partition_table
      - id: padding
        size: (-len_section % 4)
        doc: additional padding to keep partitions 4 byte aligned
  partition_table:
    seq:
      - id: table_version
        type: u4
      - id: major_version
        type: u4
      - id: minor_version
        type: u4
      - id: bugfix_version
        type: u4
      - id: unknown1
        type: u4
      - id: unknown2
        type: u4
      - id: unknown3
        type: u4
      - id: unknown4
        type: u4
      - id: unknown5
        type: u4
      - id: num_entries
        type: u4
      - id: partition_entries
        type: partition_entry
        repeat: expr
        repeat-expr: num_entries
  partition_entry:
    seq:
      - id: device
        type: u2
      - id: volume_type
        type: u2
      - id: volume
        type: u2
      - id: unknown
        type: u2
      - id: len_volume
        type: u4
      - id: volume_action
        type: u4
      - id: volume_name
        type: strz
        size: 32
      - id: mount_name
        type: strz
        size: 32
enums:
  section_types:
    0x0: section0
    0x1: section1
    0x2: section2
    0x3: section3
    0x4: section4 # data for the web server?
    0x5: section5 # directory names?
    0x6: section6
    0x7: section7
    0x8: section8
    0x9: section9
    0xa: section10
    0xb: section11 # partition table
    0xc: section12
  file_types:
    0: unknown
    1: executable
    2: archive
