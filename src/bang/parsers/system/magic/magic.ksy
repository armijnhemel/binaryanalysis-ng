meta:
  id: magic
  title: Magic database
  file-extension: .mgc
  license: BSD
  ks-version: 0.9
  encoding: ASCII
  endian: le
doc-ref:
  - https://github.com/file/file/blob/master/src/file.h
  - https://github.com/file/file/blob/master/src/apprentice.c
seq:
  - id: header
    type: header
  - id: magic
    type: magic_type
    repeat: unti
    repeat-until: _io.eof
types:
  header:
    seq:
       - id: signature
         size: 4
         contents: [0x1c, 0x04, 0x1e, 0xf1]
       - id: version
         type: u4
         valid:
           any-of: [12, 13, 14, 15, 16, 17, 18]
       - id: rest_of_header
         type:
           switch-on: version
           cases:
             12: header_12
             13: header_13
             14: header_14
             15: header_15
             16: header_15
             17: header_15
             18: header_15
  header_12:
    seq:
      - id: data
        size: 240
  header_13:
    seq:
      - id: data
        size: 304
  header_14:
    seq:
      - id: data
        size: 336
  header_15:
    seq:
      - id: data
        size: 368
  magic_type:
    seq:
      - id: common
        type: magic_type_common
      - id: version_specific
        type:
          switch-on: _root.header.version
          cases:
            12: magic_type_12_13
            13: magic_type_12_13
            14: magic_type_14
            15: magic_type_15
            16: magic_type_15
            17: magic_type_15
            18: magic_type_15
  magic_type_common:
    seq:
      # word 1
      - id: continuation_level
        type: u2
      - id: flag
        type: u1
      - id: factor
        type: u1
      # word 2
      - id: relation
        type: u1
      - id: len_string
        type: u1
      - id: comparison_type
        type: u1
        enum: comparison_types
      - id: indirection_type
        type: u1
      # word 3
      - id: indirection_operator
        type: u1
      - id: mask_operator
        type: u1
      - id: conditional_or_dummy
        type: u1
      - id: factor_operator
        type: u1
      # word 4
      - id: ofs_magic_number
        type: u4
      # word 5
      - id: ofs_from_indirection
        type: u4
      # word 6
      - id: line_number
        type: u4
      # word 7, 8
      - id: mask
        type: u8
        if: not is_string
      # word 7
      - id: line_count
        type: u4
        if: is_string
      # word 8
      - id: modifier_flags
        type: u4
        if: is_string
    instances:
      is_string: 
        value: comparison_type == comparison_types::file_string or
               comparison_type == comparison_types::file_pstring or
               comparison_type == comparison_types::file_bestring16 or
               comparison_type == comparison_types::file_lestring16 or
               comparison_type == comparison_types::file_regex or
               comparison_type == comparison_types::file_search or
               comparison_type == comparison_types::file_indirect or
               comparison_type == comparison_types::file_name or
               comparison_type == comparison_types::file_use
      in_dir:
        value: flag & 0x01 == 0x01
      off_add:
        value: flag & 0x02 == 0x02
      indir_off_add:
        value: flag & 0x04 == 0x04
      unsigned:
        value: flag & 0x08 == 0x08
      no_space:
        value: flag & 0x10 == 0x10
      bin_test:
        value: flag & 0x20 == 0x20
      text_test:
        value: flag & 0x40 == 0x40
      off_negative:
        value: flag & 0x80 == 0x80
  magic_type_12_13:
    seq:
      # words 9-24
      - id: value
        size: 64
        type:
          switch-on: _parent.common.is_string
          cases:
            true: strz
      # words 25-40
      - id: description
        size: 64
        type: strz
      # words 41-60
      - id: mimetype
        size: 80
        type: strz
      # words 61-62
      - id: apple_creator_type
        size: 8
        type: strz
      # words 63-78
      - id: extensions
        size: 64
        if: _root.header.version > 12
  magic_type_14:
    seq:
      # words 9-24
      - id: value
        size: 96
        type:
          switch-on: _parent.common.is_string
          cases:
            true: strz
      # words 25-40
      - id: description
        size: 64
        type: strz
      # words 41-60
      - id: mimetype
        size: 80
        type: strz
      # words 61-62
      - id: apple_creator_type
        size: 8
        type: strz
      # words 63-78
      - id: extensions
        size: 64
  magic_type_15:
    seq:
      # words 9-24
      - id: value
        size: 128
        type:
          switch-on: _parent.common.is_string
          cases:
            true: strz
      # words 25-40
      - id: description
        size: 64
        type: strz
      # words 41-60
      - id: mimetype
        size: 80
        type: strz
      # words 61-62
      - id: apple_creator_type
        size: 8
        type: strz
      # words 63-78
      - id: extensions
        size: 64
enums:
  comparison_types:
    0: file_invalid
    1: file_byte
    2: file_short
    3: file_default
    4: file_long
    5: file_string
    6: file_date
    7: file_beshort
    8: file_belong
    9: file_bedate
    10: file_leshort
    11: file_lelong
    12: file_ledate
    13: file_pstring
    14: file_ldate
    15: file_beldate
    16: file_leldate
    17: file_regex
    18: file_bestring16
    19: file_lestring16
    20: file_search
    21: file_medate
    22: file_meldate
    23: file_melong
    24: file_quad
    25: file_lequad
    26: file_bequad
    27: file_qdate
    28: file_leqdate
    29: file_beqdate
    30: file_qldate
    31: file_leqldate
    32: file_beqldate
    33: file_float
    34: file_befloat
    35: file_lefloat
    36: file_double
    37: file_bedouble
    38: file_ledouble
    39: file_beid3
    40: file_leid3
    41: file_indirect
    42: file_qwdate
    43: file_leqwdate
    44: file_beqwdate
    45: file_name
    46: file_use
    47: file_clear
    48: file_der
    49: file_guid
    50: file_offset
    51: file_bevarint
    52: file_levarint
    53: file_msdosdate
    54: file_lemsdosdate
    55: file_bemsdosdate
    56: file_msdostime
    57: file_lemsdostime
    58: file_bemsdostime
    59: file_octal
