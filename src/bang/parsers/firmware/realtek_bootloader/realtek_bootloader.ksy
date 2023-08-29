meta:
  id: realtek_bootloader
  title: Realtek bootloader
  license: CC0-1.0
  endian: be
  encoding: UTF-8
doc-ref:
  - https://github.com/krzys-h/8level-WRT-1200AC-firmware-tools
  - https://github.com/jameshilliard/WECB-VZ-GPL/blob/master/rtl819x/bootcode/boot/init/rtk.h
doc: |
  Realtek RTL8198 and RTL8196C related. The docs do not always fully correspond
  to devices seen in the wild.
seq:
  - id: header
    type: header
  - id: data
    size: header.len_data
types:
  header:
    seq:
      - id: signature
        contents: 'cr6c'
      - id: load_address
        type: u4
      - id: flash_memory_address
        type: u4
      - id: len_data
        type: u4
