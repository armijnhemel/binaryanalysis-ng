meta:
  id: icu
  title: ICU stub database
  file-extension: dat
  license: CC0-1.0
  endian: le
  encoding: UTF-8
doc-ref:
  - https://android.googlesource.com/platform/external/icu/+/bdaa1c7/icu4c/source/stubdata/stubdata.c#25
  - https://android.googlesource.com/platform/external/icu/+/bdaa1c7/icu4c/source/tools/toolutil/package.cpp#441
  - https://android.googlesource.com/platform/external/icu/+/bdaa1c7/icu4c/source/common/ucmndata.h
seq:
  - id: header
    type: icu_header
  - id: num_items
    -orig-id: itemCount
    type: u4
  - id: in_entries
    -orig-id: inEntries
    type: udata_offset_toc_entry
    repeat: expr
    repeat-expr: num_items
types:
  icu_header:
    seq:
      - id: header
        type: header
      - id: udata_info
        type: udata_info
      - id: rest_of_header
        size: header.len_header - header._sizeof - udata_info.size
    instances:
      len_header:
        value: header.len_header
  header:
    seq:
      - id: len_header
        type: u2
      - id: magic1
        contents: [0xda]
      - id: magic2
        contents: [0x27]
  udata_info:
    seq:
      - id: size
        type: u2
      - id: reserved1
        type: u2
        valid: 0
      - id: endian
        type: u1
        enum: endianness
      - id: charset_family
        type: u1
      - id: size_of_uchar
        type: u1
      - id: reserved2
        type: u1
        valid: 0
      - id: data_format
        type: u4
        enum: data_formats
      - id: format_version
        type: version
      - id: data_version
        type: version
  version:
    seq:
      - id: major
        type: u1
      - id: minor
        type: u1
      - id: milli
        type: u1
      - id: micro
        type: u1
  udata_offset_toc_entry:
    seq:
      - id: ofs_name
        -orig-id: nameOffset
        type: u4
      - id: ofs_data
        -orig-id: dataOffset
        type: u4
    doc: offsets from end of header
    instances:
      name:
        pos: ofs_name + _root.header.len_header
        type: strz
      data:
        pos: ofs_data + _root.header.len_header
        type: icu_header
enums:
  endianness:
    0: little
    1: big
  # some of the data here might or might not
  # be swapped in big endian files
  data_formats:
    0x206b7242:
      id: brk
      doc: Brk
    0x446e6d43:
      id: cmnd
      doc: CmnD
    0x6f79614c:
      id: layo
      doc: Layo
    0x326d724e:
      id: nrm2
      doc: Nrm2
    0x42736552:
      id: resb
      doc: ResB
    0x50525053:
      id: sprp
      doc: sprp
    0x6c6f4355:
      id: ucol
      doc: UCol, collation data
    0x6f725055:
      id: upro
      doc: UPro
    0x6d616e70:
      id: pnam
      doc: pnam
    0x6d616e75:
      id: unam
      doc: unam
