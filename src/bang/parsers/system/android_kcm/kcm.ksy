meta:
  id: kcm
  title: Key Character Map binary
  file-extension: kcm.bin
  license: CC0-1.0
  ks-version: 0.9
  encoding: ASCII
  endian: le
doc-ref: https://android.googlesource.com/platform/build/+/android-2.3.5_r1/tools/kcm/kcm.cpp#212
seq:
  - id: magic
    size: 8
    contents: [0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x72, 0x00]
    # "keychar\x00"
  - id: endian_marker
    type: u4
    valid: 0x12345678
  - id: version
    type: u4
    valid: 2
  - id: num_keys
    type: u4
  - id: keyboard_type
    type: u1
    enum: keyboard_type
    valid:
      any-of:
        - keyboard_type::numeric
        - keyboard_type::q14
        - keyboard_type::qwerty
  - id: padding
    size: 11
  - id: keys
    type: key
    repeat: expr
    repeat-expr: num_keys
types:
  key:
    seq:
      - id: keycode
        type: u4
      - id: columns
        size: 12
enums:
  keyboard_type:
    1: numeric
    2: q14
    3: qwerty
