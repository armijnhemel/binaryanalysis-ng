meta:
  id: minifs
  title: MINIFS
  license: CC0-1.0
  endian: be
  encoding: ASCII
doc: |
  MINIFS is a file system found in certain TP-Link firmware files, such as
  RE450(V4)_210531.zip

  It consists of a header, followed by a list of file names, followed by
  meta information for each file, and then a number of LZMA compressed blobs.
  The LZMA blobs can contain the concatenated contents of multiple files.
  The meta information of a file contains an offset to the directory name,
  a file name, the LZMA blob (numbering starts at 0), the offset of the file
  in the uncompressed data and the size of the uncompressed file.
seq:
  - id: header
    type: header
    size: 32
  - id: filenames
    type: filenames
    size: header.len_filenames
  - id: inodes
    type: inode
    repeat: expr
    repeat-expr: filenames.nums
types:
  header:
    seq:
      - id: magic
        contents: "MINIFS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      - id: unknown_1
        type: u4
      - id: unknown_2
        type: u4
      - id: unknown_3
        type: u4
      - id: len_filenames
        type: u4
  filenames:
    seq:
      - id: filename
        type: strz
        repeat: eos
    instances:
      nums:
        value: filename.size
  inode:
    seq:
      - id: ofs_directory
        type: u4
      - id: ofs_name
        type: u4
      - id: lzma_blob
        type: u4
      - id: ofs_file
        type: u4
      - id: uncompressed_size
        type: u4
    instances:
      filename:
        pos: ofs_name
        type: strz
        io: _root.filenames._io
      directory_name:
        pos: ofs_directory
        type: strz
        io: _root.filenames._io
