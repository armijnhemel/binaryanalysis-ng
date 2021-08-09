meta:
  id: littlefs
  title: littlefs version 1
  license: CC0-1.0
  endian: le
  encoding: ASCII
doc: |
  mkfs: https://github.com/whitecatboard/Lua-RTOS-ESP32/blob/master/components/mklfs/src/mklfs.c
doc-ref:
  - https://github.com/littlefs-project/littlefs/blob/10dfc36f08081274e37133107fff3a14d180b5e4/DESIGN.md
  - https://github.com/littlefs-project/littlefs/blob/10dfc36f08081274e37133107fff3a14d180b5e4/SPEC.md
seq:
  - id: metadata
    type: metadata
types:
  metadata:
    seq:
      - id: revision_count
        type: u4
      - id: len_dir
        type: u4
      - id: pointers
        type: u4
        repeat: expr
        repeat-expr: 2
      - id: entry
        type: entry
      - id: crc
        type: u4
  entry:
    seq:
      - id: entry_type
        type: u1
      - id: entry_body
        type:
          switch-on: entry_type
          cases:
            0x2e: superblock_body
  entry_body:
    seq:
      - id: len_entry
        type: u1
      - id: len_attribute
        type: u1
      - id: len_name
        type: u1
      - id: entry_data
        size: len_entry
      - id: attribute_bytes
        size: len_attribute
      - id: name
        size: len_name
        type: strz
  superblock_body:
    seq:
      - id: len_entry
        type: u1
        valid: 20
      - id: len_attribute
        type: u1
      - id: len_name
        type: u1
        valid: 8
      - id: root_directories
        type: u4
        repeat: expr
        repeat-expr: 2
      - id: block_size
        type: u4
      - id: block_count
        type: u4
      - id: version
        type: version
      - id: attribute_bytes
        size: len_attribute
      - id: magic
        contents: "littlefs"
  version:
    seq:
      - id: minor
        type: u2
      - id: major
        type: u2
