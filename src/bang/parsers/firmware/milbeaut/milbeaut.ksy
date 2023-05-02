meta:
  id: milbeaut
  title: Socionext Milbeaut firmware format
  license: CC-1.0
  endian: le
  encoding: UTF-8
doc: |
  A reverse engineered file format used by Socionext for their Milbeaut
  SoC platform. One prominent user of this platform is GoPro. The firmware
  this specification was derived from is the Hero 9 (GoPro Labs firmware).

  <https://community.gopro.com/html/assets/LABS_HERO9_01_60_70.zip>
seq:
  - id: magic
    contents: "MILBEAUT"
  - id: unknown
    type: u4
  - id: len_data
    type: u4
  - id: data
    size: len_data
