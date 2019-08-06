meta:
    id: cpio_new_crc
    endian: be
seq:
    - id: entries
      type: cpio_new_crc_header_and_file
      repeat: until
      repeat-until: _.filename == "TRAILER!!!"
types:
    cpio_new_crc_header_and_file:
        seq:
            - id: header
              type: cpio_new_crc_header
            - id: filename
              # new ascii: The pathname is followed by NUL bytes so that the total size of the fixed header plus pathname is a multiple of four. Likewise, the file data is padded to a multiple of four bytes. 
              # new crc: same
              type: str
              encoding: ascii
              size: header.namesize.to_i(16)
              terminator: 0
              # old binary: rounded up to even number
              # size: '(header.namesize.to_i(16) & 0x01 == 0) ? (header.namesize.to_i(16)) : (header.namesize.to_i(16) + 1)'
            - id: filename_padding
              size: '4 - (( header.namesize.to_i(16) + 13*8+6 ) % 4)'
            - id: filedata
              size: header.filesize.to_i(16)
            - id: filedata_padding
              size: 4 - (header.filesize.to_i(16) % 4)
    cpio_new_crc_header:
      seq:
            - id: magic
              contents: "070702"
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


