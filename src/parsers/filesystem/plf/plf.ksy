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
  - https://web.archive.org/web/20210907153741/https://titanwolf.org/Network/Articles/Article?AID=a7225440-da3a-45e8-89c3-c098b93e7fc2#gsc.tab=0
  - https://github.com/Parrot-Developers/libARUpdater/blob/5b3667dd97c4ba0e38cb5f9a477773012c1e55d3/Sources/ARUPDATER_Plf.h
  - https://github.com/Parrot-Developers/libpuf/blob/master/src/libpuf_plf.h
  - https://github.com/scorp2kk/ardrone-tool
seq:
  - id: header
    type: header
  - id: padding
    size: header.len_header - header._sizeof
  - id: partitions
    type: partition
    #repeat: expr
    #repeat-expr: 1
types:
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
        - id: len_entry
          type: u4
        - id: crc32
          type: u4
        - id: unknown1
          type: u4
        - id: uncompressed_size
          type: u4
        - id: data
          size: len_entry
          type:
            switch-on: section_type
            cases:
              section_types::boot_configuration: dummy
        - id: padding
          size: 0
          doc: additional padding to keep partitions 4 byte aligned
  dummy: {}
enums:
  section_types:
    0x5: directory_names
    0x7: boot_configuration
    0xb: partition_table
    0xc: installer
  file_types:
    1: executable
    2: archive
