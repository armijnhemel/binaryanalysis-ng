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
seq:
  - id: header
    type: header
  - id: udata_info
    type: udata_info
  - id: rest_of_header
    size: header.size - header._sizeof - udata_info._sizeof
  - id: in_entries
    -orig-id: inEntries
    type: u4
instances:
  endian:
    value: udata_info.endian
types:
  header:
    seq:
      - id: size
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
        #valid: 0
        # only support little endian now
      - id: charset_family
        type: u1
      - id: size_of_uchar
        type: u1
      - id: reserved2
        type: u1
        valid: 0
      - id: data_format
        size: 4
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
enums:
  endianness:
    0: little
    1: big
