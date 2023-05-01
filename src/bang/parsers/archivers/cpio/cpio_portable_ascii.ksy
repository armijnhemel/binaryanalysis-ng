meta:
  id: cpio_portable_ascii
  ks-opaque-types: true
instances:
  trailing_filename:
    value: '"TRAILER!!!"'
seq:
  - id: entries
    type: cpio_portable_ascii_header_and_file
    repeat: until
    repeat-until: _.filename == trailing_filename and _.header.fsize == 0
types:
  cpio_portable_ascii_header_and_file:
    seq:
     - id: header
       type: cpio_portable_ascii_header
     - id: filename
       type: str
       encoding: ascii
       size: header.nsize
       terminator: 0
       # Unlike the old binary format, there is no additional padding after the pathname or file contents.
     - id: filedata
       #type: skip_and_ignore_type
       size: header.fsize
  cpio_portable_ascii_header:
    seq:
      - id: magic
        contents: "070707"
      - id: dev
        type: str
        size: 6
        encoding: ascii
      - id: ino
        type: str
        size: 6
        encoding: ascii
      - id: mode
        type: str
        size: 6
        encoding: ascii
      - id: uid
        type: str
        size: 6
        encoding: ascii
      - id: gid
        type: str
        size: 6
        encoding: ascii
      - id: nlink
        type: str
        size: 6
        encoding: ascii
      - id: rdev
        type: str
        size: 6
        encoding: ascii
      - id: mtime
        type: str
        size: 11
        encoding: ascii
      - id: namesize
        type: str
        size: 6
        encoding: ascii
      - id: filesize
        type: str
        size: 11
        encoding: ascii
    instances:
      hsize:
        value: 2*11 + 9*6
      fsize:
        value: filesize.to_i(8)
      nsize:
        value: namesize.to_i(8)
      npaddingsize:
        value: 0
      fpaddingsize:
        value: 0
      bsize:
        value: hsize + nsize + npaddingsize + fsize + fpaddingsize
      cpio_mode:
        value: mode.to_i(8)
