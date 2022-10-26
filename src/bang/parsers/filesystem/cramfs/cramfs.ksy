meta:
  id: cramfs
  title: Compressed ROM filesystem
  license: CC0
  encoding: ASCII
seq:
  - id: magic
    type: u4be
    enum: magic
    valid:
      any-of:
        - magic::big
        - magic::little
  - id: header
    type: endian_header
  - id: data
    size: header.len_cramfs - magic._sizeof - header._sizeof
    type: inodes(header.num_files)
types:
  endian_header:
    meta:
      endian:
        switch-on: _root.magic
        cases:
          'magic::little': le
          'magic::big': be
    seq:
      - id: len_cramfs
        type: u4
      - id: feature_flags
        type: u4
      - id: reserved
        size: 4
      - id: signature
        contents: "Compressed ROMFS"
      - id: crc32
        type: u4
      - id: edition
        type: u4
      - id: num_blocks
        type: u4
      - id: num_files
        type: u4
      - id: user_defined_name
        type: strz
        size: 16
    instances:
      version:
        value: 'feature_flags & 1 == 1 ? 2: 0'
  inodes:
    meta:
      endian:
        switch-on: _root.magic
        cases:
          'magic::little': le
          'magic::big': be
    params:
      - id: num_files
        type: u4
    seq:
      - id: inodes
        type: inode
        repeat: expr
        repeat-expr: num_files
    types:
      inode:
        seq:
          - id: mode
            type: u2
          - id: uid
            type: u2
          - id: len_decompressed
            type: b24
          - id: gid
            type: u1
          - id: name_length
            type: u4
          - id: name
            type: strz
            size: len_name
        instances:
          len_name:
            value: |
              _root.magic == magic::big ? ((name_length & 4227858432) >> 26) * 4:
              (name_length & 63) * 4
          ofs_data:
            value: |
              _root.magic == magic::big ? (name_length & 67108863) * 4:
              ((name_length & 67108863) >> 6) * 4
enums:
  magic:
    0x453dcd28: little
    0x28cd3d45: big
