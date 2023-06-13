meta:
  id: ambarella
  title: Ambarella image format
  license: CC0-1.0
  endian: le
doc-ref:
  - http://web.archive.org/web/20190402224117/https://courses.cs.ut.ee/MTAT.07.022/2015_spring/uploads/Main/karl-report-s15.pdf (section 4.2)
  - http://web.archive.org/web/20140627194326/http://forum.dashcamtalk.com/threads/r-d-a7-r-d-thread.5119/page-2 (post #28)
seq:
  - id: start_offsets
    type: u4
    repeat: expr
    repeat-expr: 32
  - id: end_offsets
    type: u4
    repeat: expr
    repeat-expr: 32
instances:
  sections:
    type: section_data(_index)
    repeat: expr
    repeat-expr: 32
types:
  section_data:
    params:
      - id: i
        type: u4
    instances:
      body:
        pos: _parent.start_offsets[i]
        size: _parent.end_offsets[i] - _parent.start_offsets[i]
        type: section
        if: _parent.start_offsets[i] != 0
  section:
    seq:
      - id: header
        type: section_header
        size: 256
      - id: data
        size: header.len_data
  section_header:
    seq:
      - id: crc32
        type: u4
      - id: version
        type: u4
      - id: build_date
        type: u4
      - id: len_data
        type: u4
      - id: memory_location
        type: u4
      - id: flags
        type: u4
      - id: magic
        size: 4
        contents: [0x90, 0xeb, 0x24, 0xa3]
      - id: flags_2
        type: u4
