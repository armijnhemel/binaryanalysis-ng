meta:
  id: gvariant
  title: GVariant
  license: LGPL-2.1-or-later
  endian: le
doc-ref: https://github.com/GNOME/gvdb/blob/main/gvdb/gvdb-format.h
seq:
  - id: signature
    contents: 'GVariant'
  - id: version
    type: u4
  - id: options
    type: u4
  - id: root
    type: pointer
types:
  pointer:
    seq:
      - id: start
        type: u4
      - id: end
        type: u4
    instances:
      data:
        pos: start
        size: end - start
        type: hash_header
  hash_header:
    seq:
      - id: num_bloom_words
        type: u4
      - id: num_buckets
        type: u4
