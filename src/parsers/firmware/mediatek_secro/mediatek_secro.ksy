meta:
  id: mediatek_secro
  title: Mediatek secro.img
  file-extension: img
  tags:
    - android
    - mediatek
  license: CC0
  encoding: UTF-8
  endian: le
doc: |
  Format of secro.bin files found on (older) MediaTek based devices

doc-ref:
  - https://android.googlesource.com/kernel/mediatek/+/0164f13d76f1966b140ea06261ea6f63c073e080/drivers/misc/mediatek/masp/asf/asf_inc/sec_secroimg.h
seq:
  - id: header
    type: header
instances:
  region:
    pos: header.ofs_region
    size: header.len_region
  hash:
    pos: header.ofs_hash
    size: header.len_hash
  andro:
    pos: header.ofs_andro
    size: header.len_andro
  md:
    pos: header.ofs_md
    size: header.len_md
  md2:
    pos: header.ofs_md2
    size: header.len_md2
types:
  header:
    seq:
      - id: mediatek_id
        size: 16
        contents: ["AND_AC_REGION", 0, 0, 0]
      - id: magic
        contents: [0x48, 0x48, 0x48, 0x48]
      - id: len_region
        type: u4
      - id: ofs_region
        type: u4
      - id: len_hash
        type: u4
      - id: ofs_hash
        type: u4
      - id: len_andro
        type: u4
      - id: ofs_andro
        type: u4
      - id: len_md
        type: u4
      - id: ofs_md
        type: u4
      - id: len_md2
        type: u4
      - id: ofs_md2
        type: u4
      - id: world_phone_support
        size: 1
      - id: world_phone_md_count
        size: 1
      - id: reserved
        contents: [0, 0]
