meta:
  id: zisofs
  title: zisofs
  license: CC0-1.0
  endian: le
doc: |
  zisofs is a compression format for files on ISO9660 file system. It has
  limited support across operating systems, mainly Linux kernel. Typically a
  directory tree is first preprocessed by mkzftree (from the zisofs-tools
  package before being turned into an ISO9660 image by mkisofs, genisoimage
  or similar tool. The data is zlib compressed.

  The specification here describes the structure of a file that has been
  preprocessed by mkzftree, not of a full ISO9660 ziso. Data is not
  decompressed, as blocks with length 0 have a special meaning. Decompressing
  and deconstruction this data should be done outside of Kaitai Struct.
doc-ref: https://web.archive.org/web/20200612093441/https://dev.lovelyhq.com/libburnia/web/-/wikis/zisofs
seq:
  - id: header
    type: header
    size: 16
  - id: block_pointers
    type: u4
    repeat: expr
    repeat-expr: header.num_block_pointers
  - id: final_block_pointer
    type: u4
    doc: |
      Final pointer indicating the first invalid byte. Typically this is
      also the end of the file data.
instances:
  blocks:
    type: block_pointer(_index)
    repeat: expr
    repeat-expr: header.num_block_pointers
types:
  header:
    seq:
      - id: magic
        contents: [0x37, 0xe4, 0x53, 0x96, 0xc9, 0xdb, 0xd6, 0x07]
      - id: uncompressed_size
        type: u4
        doc: Size of the original uncompressed file
      - id: len_header
        type: u1
        valid: 4
        doc: header_size >> 2 (currently 4)
      - id: log2_block_size
        type: u1
        valid:
          any-of: [15, 16, 17]
      - id: reserved
        contents: [0, 0]
    instances:
      block_size:
        value: 2 << (log2_block_size - 1)
      num_block_pointers:
        value: 'uncompressed_size % block_size == 0 ? (uncompressed_size / block_size) : (uncompressed_size / block_size) + 1'
        doc: ceil(uncompressed_size / block_size)
  block_pointer:
    params:
      - id: index
        type: u4
    instances:
      len_block:
        value: 'index < _parent.block_pointers.size - 1 ? _parent.block_pointers[index+1] - _parent.block_pointers[index] : _parent.final_block_pointer - _parent.block_pointers[index]'
      data:
        pos: _parent.block_pointers[index]
        io: _root._io
        size: len_block
