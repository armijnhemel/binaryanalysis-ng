meta:
  id: anjvision
  title: ANJVision firmware image
  endian: le
  license: CC0-1.0
doc: |
  ANJVision is a Chinese manufacturer of IP cameras. The company uses
  its own firmware format, which is a fairly simple wrapper around U-boot
  and a file system. So far the only observed file system is Squashfs.
seq:
  - id: header
    type: header
  - id: rest_of_header
    size: header.len_header - header._sizeof
  - id: uboot
    size: header.len_data
  - id: file_system
    size: header.len_file - header.len_data - header.len_header
types:
  header:
    seq:
      - id: magic
        contents: 'ANJOY888'
      - id: unknown
        size: 4
      - id: len_file
        type: u4
      - id: unknown_1
        type: u4
        valid: 3
      - id: len_header
        type: u4
      - id: len_data
        type: u4
      - id: unknown_2
        type: u4
