meta:
  id: novatek
  title: Novatek
  license: CC0-1.0
  endian: be
  encoding: ASCII
doc: |
  An incomplete parser for firmware files for Novatek chipset based
  devices (dashcams, etc.). The file format seems to be somewhat based
  on the BCL library, although it seems there were modifications.

  Only LZ77 compression seems to be used.
doc-ref:
  - https://web.archive.org/web/20210516004049/https://limkopi.me/analysing-sj4000s-firmware/
seq:
  - id: magic
    contents: "BCL1"
  - id: unknown
    type: u2
  - id: compression
    type: u2
    enum: compression_method
    valid:
      any-of:
        - compression_method::lz77
  - id: len_original
    type: u4
  - id: len_data
    type: u4
  - id: data
    size: len_data
enums:
  compression_method:
    1: rle
    2: huffman
    3: rice8
    4: rice16
    5: rice32
    6: rice8signed
    7: rice16signed
    8: rice32signed
    9: lz77
    10: shannonfano
