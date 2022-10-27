meta:
  id: cramfs
  title: Compressed ROM filesystem
  license: CC0
  encoding: UTF-8
doc-ref:
  - https://github.com/npitre/cramfs-tools
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
instances:
  block_size:
    value: 4096
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
      - id: volume_name
        type: strz
        size: 16
    instances:
      version:
        value: 'feature_flags & 1 == 1 ? 2: 0'
      sorted_dirs:
        value: feature_flags & 2 == 2
      holes:
        value: feature_flags & 0x100 == 0x100
      shifted_root_offset:
        value: feature_flags & 0x400 == 0x400
      block_pointer_extensions:
        value: feature_flags & 0x800 == 0x800
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
            type:
              switch-on: _root.magic
              cases:
                'magic::little': b24le
                'magic::big': b24be
          - id: gid
            type: u1
          - id: name_length
            type: u4
          - id: name
            type: strz
            size: len_name
        instances:
          # length of the name and offset. The first 6 bits are for
          # the name length (divided by 4), the last 26 bits for the
          # offset of the data (divided by 4). This is regardless of
          # the endianness!
          # The name is padded to 4 bytes. Because the original name length
          # is restored by multiplying with 4 there is no need for a
          # check for padding.
          file_mode:
            value: mode & 0o0170000
            enum: modes
          len_name:
            value: |
              _root.magic == magic::big ? ((name_length & 4227858432) >> 26) * 4:
              (name_length & 63) * 4
          ofs_data:
            value: |
              _root.magic == magic::big ? (name_length & 67108863) * 4:
              ((name_length & 67108863) >> 6) * 4
          block_pointers:
            pos: ofs_data
            io: _root._io
            type: block_pointers
            size: nblocks * 4
            if: file_mode == modes::regular or file_mode == modes::link
          nblocks:
            value: ((len_decompressed - 1) / _root.block_size) + 1
      block_pointers:
        seq:
          - id: block_pointers
            type: u4
            repeat: eos
enums:
  magic:
    0x453dcd28: little
    0x28cd3d45: big
  modes:
    0xc000: socket
    0xa000: link
    0x8000: regular
    0x6000: block_device
    0x4000: directory
    0x2000: character_device
    0x1000: fifo
