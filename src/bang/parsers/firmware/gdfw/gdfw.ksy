meta:
  id: gdfw
  title: Granite Devices firmware
  license: CC0-1.0
  endian: le
  encoding: UTF-8
doc-ref:
  - https://granitedevices.com/wiki/Firmware_file_format_(.gdf)
seq:
  - id: header
    type: header
  - id: hostfw
    size: header.len_hostfw
  - id: gcfw
    size: header.len_gcfw
  - id: checksum
    type: u4
types:
  header:
    seq:
      - id: magic
        contents: 'GDFW'
      - id: version
        type: u2
        valid: 300
      - id: target_drive_type
        type: u2
        enum: target_drive_types
        valid:
          any-of:
            - target_drive_types::argon
            - target_drive_types::ion
            - target_drive_types::atomi
      - id: len_hostfw
        type: u4
      - id: gcfw_len
        type: u4
    instances:
      len_gcfw:
        value: 'gcfw_len == 0xffffffff ? 0 : gcfw_len'
enums:
  target_drive_types:
     4000: argon
     11000: ion
     14000: atomi
