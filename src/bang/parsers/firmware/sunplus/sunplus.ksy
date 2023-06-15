meta:
  id: sunplus
  title: Sunplus firmware
  endian: le
doc-ref:
  - https://web.archive.org/web/20210301164514/https://www.goprawn.com/forum/sunplus-cams/10333-icatch-sunplus-firmware-hacks
  - https://github.com/Linouth/iCatch-V50-Playground
seq:
  - id: header
    type: header
    size: 1024
  - id: isp_bootloader
    size: header.ofs_aimg - header._sizeof
  - id: aimg
    size: len_aimg
  - id: bimg
    size: len_bimg
  - id: cimg
    size: len_cimg
    if: header.ofs_cimg != 0
  - id: bin
    size: len_bin
    if: header.ofs_bin != 0
  - id: bad_pixel
    size: len_bad_pixel
  - id: dram
    size: len_dram
instances:
  raw_header:
    pos: 0
    size: 1024
  len_aimg:
    value: header.ofs_bimg - header.ofs_aimg
  len_bimg:
    value: 'header.ofs_cimg == 0 ? header.ofs_bin - header.ofs_bimg : header.ofs_cimg - header.ofs_bimg'
  len_cimg:
    value: 'header.ofs_bin == 0 ? header.ofs_bad_pixel - header.ofs_cimg : header.ofs_bin - header.ofs_cimg'
  len_bin:
    value: 'header.ofs_bin == 0 ? 0 : header.ofs_bad_pixel - header.ofs_bin'
  len_bad_pixel:
    value: header.ofs_dram - header.ofs_bad_pixel
  len_dram:
    value: header.len_firmware - header.ofs_dram
types:
  header:
    seq:
      - id: magic
        contents: ['SUNP BURN FILE', 0, 0]
      - id: len_firmware
        type: u4
      - id: ofs_aimg
        type: u4
      - id: ofs_bimg
        type: u4
      - id: ofs_cimg
        type: u4
      - id: ofs_bin
        type: u4
      - id: ofs_bad_pixel
        type: u4
      - id: ofs_dram
        type: u4
