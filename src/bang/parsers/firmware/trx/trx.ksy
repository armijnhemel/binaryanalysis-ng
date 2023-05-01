meta:
  id: trx
  title: Broadcom .trx file format
  file-extension: trx
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc-ref:
  - https://web.archive.org/web/20190127154419/https://openwrt.org/docs/techref/header
seq:
  - id: preheader
    type: preheader
  - id: header_and_data
    size: preheader.len_trx - preheader._sizeof
    type: header_and_data
instances:
  raw_data:
    pos: preheader._sizeof
    size: preheader.len_trx - preheader._sizeof
types:
  preheader:
    seq:
      - id: magic
        contents: 'HDR0'
      - id: len_trx
        type: u4
      - id: crc32
        type: u4
  header_and_data:
    seq:
      - id: header
        type: header
      - id: data
        size-eos: true
  header:
    seq:
      - id: flags
        type: u2
      - id: version
        type: u2
        valid:
          any-of: [1, 2]
      - id: ofs_partition0
        type: u4
        valid:
          expr: _ == 0 or _ >= len_header
      - id: ofs_partition1
        type: u4
        valid:
          expr: _ == 0 or (_ >= len_header and _ >= ofs_partition0)
      - id: ofs_partition2
        type: u4
        valid:
          expr: _ == 0 or (_ >= len_header and _ >= ofs_partition1)
      - id: offset_partition3
        type: u4
        if: version > 1
        valid:
          expr: _ == 0 or (_ >= len_header and _ >= ofs_partition2)
    instances:
      len_header:
        value: 'version == 1 ? 28 : 32'
      partition0:
        pos: ofs_partition0
        size: 'ofs_partition1 == 0 ? _root.preheader.len_trx - ofs_partition0 : ofs_partition1 - ofs_partition0'
        io: _root._io
        if: ofs_partition0 != 0
      partition1:
        pos: ofs_partition1
        size: 'ofs_partition2 == 0 ? _root.preheader.len_trx - ofs_partition1 : ofs_partition2 - ofs_partition1'
        io: _root._io
        if: ofs_partition1 != 0
      partition2:
        pos: ofs_partition2
        size: 'ofs_partition3 == 0 ? _root.preheader.len_trx - ofs_partition2 : ofs_partition3 - ofs_partition2'
        io: _root._io
        if: ofs_partition2 != 0
      partition3:
        pos: ofs_partition3
        size: _root.preheader.len_trx - ofs_partition3
        io: _root._io
        if: version > 1 and ofs_partition3 != 0
      ofs_partition3:
        value: 'version > 1 ? offset_partition3: 0'
