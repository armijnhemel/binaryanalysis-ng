meta:
  id: jffs2
  title: JFFS2 inode
  tags:
    - file system
    - linux
  license: CC0-1.0
  ks-version: 0.9
seq:
  - id: magic
    type: u2be
    enum: magic
    valid:
      any-of:
        - magic::be
        - magic::le
        - magic::dirty
  - id: header
    type: inode_header
  - id: data
    type:
      switch-on: header.inode_type
      cases:
        'inode_type::dirent': dirent
        'inode_type::inode': inode
    size: header.len_inode - header._sizeof - magic._sizeof
types:
  inode_header:
    meta:
      endian:
        switch-on: _root.magic
        cases:
          'magic::le': le
          'magic::be': be
    seq:
      - id: inode_type
        type: u2
        enum: inode_type
      - id: len_inode
        type: u4
  dirent:
    meta:
      endian:
        switch-on: _root.magic
        cases:
          'magic::le': le
          'magic::be': be
    seq:
      - id: header_crc
        type: u4
      - id: parent_inode
        type: u4
      - id: inode_version
        type: u4
      - id: inode_number
        type: u4
      - id: mctime
        type: u4
      - id: len_name
        type: u1
      - id: dirent_type
        type: u1
      - id: unused
        size: 2
      - id: node_crc
        type: u4
      - id: name_crc
        type: u4
      - id: name
        size: len_name
  inode:
    meta:
      endian:
        switch-on: _root.magic
        cases:
          'magic::le': le
          'magic::be': be
    seq:
      - id: header_crc
        type: u4
      - id: inode_number
        type: u4
      - id: inode_version
        type: u4
      - id: mode
        type: u4
      - id: uid
        type: u2
      - id: gid
        type: u2
      - id: isize
        type: u4
      - id: atime
        type: u4
      - id: mtime
        type: u4
      - id: ctime
        type: u4
      - id: body
        size-eos: true
        type:
          switch-on: file_mode
          cases:
            modes::link: regular
            modes::regular: regular
    instances:
      file_mode:
        value: mode & 0o0170000
        enum: modes
    types:
      regular:
        seq:
          - id: ofs_write
            type: u4
          - id: len_compressed
            type: u4
          - id: len_decompressed
            type: u4
          - id: compression
            type: u1
            enum: compression
            valid:
              any-of:
                - compression::no_compression
                - compression::zero
                - compression::rtime
                - compression::rubinmips
                - compression::copy
                - compression::dynrubin
                - compression::zlib
                - compression::lzo
                - compression::lzma
          - id: requested_compression
            type: u1
          - id: flags
            type: u2
          - id: data_crc
            type: u4
          - id: node_crc
            type: u4
          - id: data
            size-eos: true
enums:
  magic:
    0x0000: dirty
    0x8519: le
    0x1985: be
  inode_type:
    0xe001: dirent
    0xe002: inode
    0x2003: clean_marker
    0x2004: padding
    0x2006: summary
    0xe008: xattr
    0xe009: xref
  modes:
    0xc000: socket
    0xa000: link
    0x8000: regular
    0x6000: block_device
    0x4000: directory
    0x2000: character_device
    0x1000: fifo
  compression:
    0: no_compression
    1: zero
    2: rtime
    3: rubinmips
    4: copy
    5: dynrubin
    6: zlib
    7: lzo
    8: lzma
