meta:
  id: cpio_old_binary
  ks-opaque-types: true
  endian: le
instances:
  trailing_filename:
    value: '"TRAILER!!!"'
seq:
  - id: entries
    type: cpio_old_binary_header_and_file
    repeat: until
    repeat-until: _.filename == trailing_filename and _.header.fsize == 0
types:
  cpio_old_binary_header_and_file:
    seq:
      - id: header
        type: cpio_old_binary_header
      - id: filename
        type: str
        encoding: ascii
        size: header.nsize
        terminator: 0
      - id: filename_padding
        size: header.npaddingsize
      - id: filedata 
        #type: skip_and_ignore_type
        #size: header.fsize
        size: header.checked_filesize
      - id: filedata_padding
        size: header.fpaddingsize
  cpio_old_binary_header:
    seq:
      - id: magic
        contents: [0xc7, 0x71]
      - id: dev
        type: u2
      - id: ino
        type: u2
      - id: mode
        type: u2
      - id: uid
        type: u2
      - id: gid
        type: u2
      - id: nlink
        type: u2
      - id: rdev
        type: u2
      - id: mtime
        type: four_byte_unsigned_integer
      - id: namesize
        type: u2
      - id: filesize
        type: four_byte_unsigned_integer
    instances:
      hsize:
        value: 9*2+2*4
      fsize:
        value: filesize.value
      nsize:
        value: namesize
      npaddingsize:
        value: (nsize % 2)
      fpaddingsize:
        value: (fsize % 2)
      bsize:
        value: hsize + nsize + npaddingsize + fsize + fpaddingsize
      cpio_mode:
        value: mode
      checked_filesize:
        value: '(fsize < _root._io.size) ? fsize : -1'
  four_byte_unsigned_integer:
    seq:
      - id: msb
        type: u2
      - id: lsb
        type: u2
    instances:
      value:
        value: lsb + (msb << 16)
