meta:
  id: bflt
  title: BFLT
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: be
doc-ref:
  - https://web.archive.org/web/20120123212024/http://retired.beyondlogic.org/uClinux/bflt.htm
  - http://web.archive.org/web/20180317070540/https://blog.tangrs.id.au/2012/04/07/bflt-format-implementation-notes/
seq:
  - id: header
    type: header
    size: 64
instances:
  text:
    pos: header.ofs_entry
    size: len_text
    if: not header.gzip
  len_text:
    value: header.ofs_data_start - header.ofs_entry
  data:
    pos: header.ofs_data_start
    size: len_data
    if: not (header.gzip or header.gzdata)
  len_data:
    value: header.ofs_data_end - header.ofs_data_start
  relocations:
    pos: header.ofs_reloc_start
    type: relocations
    if: not (header.gzip or header.gzdata)
types:
  relocations:
    seq:
      - id: relocation
        type: u4
        repeat: expr
        repeat-expr: _root.header.reloc_count
  header:
    seq:
      - id: magic
        contents: "bFLT"
      - id: version
        type: u4
        valid: 4
      - id: ofs_entry
        type: u4
        doc: |
          Offset of first executable instruction with
          text segment from beginning of filed
      - id: ofs_data_start
        type: u4
        doc:  Offset of data segment from beginning of file
      - id: ofs_data_end
        type: u4
        doc: Offset of end of data segment from beginning of file
      - id: ofs_bss_end
        type: u4
        doc: Offset of end of data segment from beginning of file
      - id: stack_size
        type: u4
        doc: Size of stack, in bytes
      - id: ofs_reloc_start
        type: u4
        doc: Offset of relocation records from beginning of file
      - id: reloc_count
        type: u4
        doc: Number of relocation records
      - id: flags
        type: u4
      - id: build_date
        type: u4
      - id: filler
        contents: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    instances:
      load_into_ram:
        value: flags & 0x1 == 1
        doc: load program entirely into RAM
      got_pic:
        value: flags & 0x2 == 2
        doc: program is PIC with GOT
      gzip:
        value: flags & 0x4 == 4
        doc: all but the header is compressed
      gzdata:
        value: flags & 0x8 == 8
        doc: only data/relocs are compressed (for XIP)
      ktrace:
        value: flags & 0x10 == 0x10
        doc: output useful kernel trace for debugging
