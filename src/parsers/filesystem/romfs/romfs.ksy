meta:
  id: romfs
  title: romfs
  license: GPL-2.0
  encoding: ASCII
  endian: be
doc-ref: https://www.kernel.org/doc/Documentation/filesystems/romfs.rst
seq:
  - id: magic
    contents: '-rom1fs-'
  - id: len_file
    type: u4
    doc: The number of accessible bytes in this fs.
  - id: checksum
    type: u4
    doc: The checksum of the FIRST 512 BYTES.
  - id: volume_name
    type: strz
  - id: padding
    size: -_io.pos % 16
  - id: files
    size: len_file - _io.pos
    type: files
types:
  files:
    seq:
      - id: files
        type: fileheader
        repeat: until
        repeat-until: _.next_fileheader == 0 or _io.eof
  fileheader:
    seq:
      - id: next_fileheader_and_flags
        type: u4
        doc: The offset of the next file header (zero if no more files)
      - id: spec_info
        type: u4
        doc: Info for directories/hard links/devices
      - id: len_file
        type: u4
        doc: The size of this file in bytes
      - id: checksum
        type: u4
        doc: Covering the meta data, including the file name, and padding
      - id: file_name
        type: strz
      - id: padding1
        size: -_io.pos % 16
      - id: data
        size: len_file
      - id: padding2
        size: -_io.pos % 16
    instances:
      next_fileheader:
        value: next_fileheader_and_flags & 4294967280
      executable:
        value: next_fileheader_and_flags & 8 == 8
      mode_info:
        value: next_fileheader_and_flags & 7
        enum: filetype
enums:
  filetype:
    0: hardlink
    1: directory
    2: regular_file
    3: symbolic_link
    4: block_device
    5: character_device
    6: socket
    7: fifo
