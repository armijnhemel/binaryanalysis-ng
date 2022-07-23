meta:
  id: lz4_legacy
  title: LZ4 legacy format
  license: CC0-1.0
  endian: le
  encoding: ASCII
doc-ref: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md#legacy-frame
doc: |
  Specification has the following notice:

  Copyright (c) 2013-2020 Yann Collet

  Permission is granted to copy and distribute this document for any purpose and
  without charge, including translations into other languages and incorporation
  into compilations, provided that the copyright notice and this notice are preserved,
  and that any substantive changes or deletions from the original are clearly
  marked. Distribution of this document is unlimited.
seq:
  - id: magic
    type: u4
    valid: 0x184c2102
  - id: blocks
    type: block
    repeat: until
    repeat-until: _io.eof or _.is_magic
    # This is ugly, as it eats some extra bytes, so an external
    # program processing this could should take this into account
types:
  block:
    seq:
      - id: len_data
        type: u4
      - id: data
        size: len_data
        if: not is_magic
    instances:
      is_magic:
        value: len_data == 0x184c2102
