meta:
  id: cpio_new_ascii
  ks-opaque-types: true
instances:
  trailing_filename:
    value: '"TRAILER!!!"'
seq:
  - id: entries
    type: cpio_new_ascii_header_and_file
    repeat: until
    repeat-until: _.filename == trailing_filename and _.header.fsize == 0
types:
  cpio_new_ascii_header_and_file:
    seq:
      - id: header
        type: cpio_new_ascii_header
      - id: filename
        # new ascii: The pathname is followed by NUL bytes so that the total
        # size of the fixed header plus pathname is a multiple of four.
        # Likewise, the file data is padded to a multiple of four bytes. 
        type: str
        encoding: ascii
        size: header.nsize
        terminator: 0
      - id: filename_padding
        size: (4 - (( header.nsize + header.hsize ) % 4)) % 4
      - id: filedata 
        # TODO: only set this type if file is regular
        # type: skip_and_ignore_type
        size: header.fsize
      - id: filedata_padding
        size: (4 - (header.fsize % 4)) % 4
  cpio_new_ascii_header:
    seq:
      - id: magic
        contents: "070701"
      - id: ino
        type: str
        size: 8
        encoding: ascii
      - id: mode
        type: str
        size: 8
        encoding: ascii
      - id: uid
        type: str
        size: 8
        encoding: ascii
      - id: gid
        type: str
        size: 8
        encoding: ascii
      - id: nlink
        type: str
        size: 8
        encoding: ascii
      - id: mtime
        type: str
        size: 8
        encoding: ascii
      - id: filesize
        type: str
        size: 8
        encoding: ascii
      - id: devmajor
        type: str
        size: 8
        encoding: ascii
      - id: devminor
        type: str
        size: 8
        encoding: ascii
      - id: rdevmajor
        type: str
        size: 8
        encoding: ascii
      - id: rdevminor
        type: str
        size: 8
        encoding: ascii
      - id: namesize
        type: str
        size: 8
        encoding: ascii
      - id: check
        type: str
        size: 8
        encoding: ascii
    instances:
      hsize:
        value: 13*8+6
      fsize:
        value: filesize.to_i(16)
      nsize:
        value: namesize.to_i(16)
      npaddingsize:
        value: '(-( nsize + hsize ) % 4)'
      fpaddingsize:
        value: (-fsize % 4)
      bsize:
        value: hsize + nsize + npaddingsize + fsize + fpaddingsize
      cpio_mode:
        value: mode.to_i(16)
