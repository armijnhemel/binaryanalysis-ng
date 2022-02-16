meta:
  id: glibc_locale_archive
  title: Glibc locale archive
  license: CC-1.0
  encoding: UTF-8
  endian: le
doc-ref:
  - https://sourceware.org/git/?p=glibc.git;a=blob;f=locale/locarchive.h;h=012ffd03f30c5f7535e8d9053afbc5c1a35acc94;hb=HEAD
seq:
  - id: magic
    type: u4
    #valid: 3724673289 # 0xde020109
  - id: serial
    type: u4

    # Name hash table
  - id: ofs_namehash
    type: u4
  - id: namehash_used
    type: u4
  - id: num_namehash
    type: u4

    # String table
  - id: ofs_string
    type: u4
  - id: string_used
    type: u4
  - id: num_string
    type: u4

    # Table with locale records
  - id: ofs_locrectab
    type: u4
  - id: locrectab_used
    type: u4
  - id: num_locrectab
    type: u4

    # MD5 sum hash table
  - id: ofs_sumhash
    type: u4
  - id: sumhash_used
    type: u4
  - id: num_sumhash
    type: u4

instances:
  lc_last:
    value: 13
  name_hash_table:
    pos: ofs_namehash
    size: ofs_string - ofs_namehash
    type: name_hash_table(num_namehash)
  string_table:
    pos: ofs_string
    size: ofs_locrectab - ofs_string
    type: string_table(namehash_used)
  locrec_table:
    pos: ofs_locrectab
    size: ofs_sumhash - ofs_locrectab
  md5_table:
    pos: ofs_sumhash
    type: md5_table(num_sumhash)

types:
  md5_table:
    params:
      - id: num_md5
        type: u4
    seq:
      - id: entries
        type: sum_hash_entry
        repeat: expr
        repeat-expr: num_md5
  string_table:
    params:
      - id: num_string
        type: u4
    seq:
      - id: entries
        type: strz
        repeat: expr
        repeat-expr: num_string
  name_hash_table:
    params:
      - id: num_namehash
        type: u4
    seq:
      - id: entries
        type: name_hash_entry
        repeat: expr
        repeat-expr: num_namehash
  name_hash_entry:
    -webide-representation: "{name} {hash_value}"
    seq:
      - id: hash_value
        type: u4
        doc: Hash value of the name.
      - id: ofs_name
        type: u4
        doc: Offset of the name in the string table.
      - id: ofs_locrec
        type: u4
        doc: Offset of the locale record.
    instances:
      name:
        io: _root._io
        pos: ofs_name
        type: strz
        if: ofs_name != 0
        -webide-parse-mode: eager
      locrec:
        io: _root._io
        pos: ofs_locrec
        type: loc_rec_entry
        if: ofs_locrec != 0
  loc_rec_entry:
    seq:
      - id: references
        type: u4
        doc: number of namehashent records that point here
      - id: loc_recs
        type: loc_rec
        repeat: expr
        repeat-expr: _root.lc_last
  loc_rec:
    seq:
      - id: ofs_locrec
        type: u4
      - id: len_locrec
        type: u4
    instances:
      loc_rec:
        io: _root._io
        pos: ofs_locrec
        size: len_locrec
      loc_rec_type:
        io: _root._io
        pos: ofs_locrec
        type: u4
        enum: category
  sum_hash_entry:
    seq:
      - id: md5
        size: 16
        doc: MD5 sum
      - id: ofs_entry
        type: u4
        doc: Offset of the file in the archive.
    #instances:
      #entry:
        #io: _root._io
        #pos: ofs_entry
        #size: 4 # no idea what this size should be
        #if: ofs_entry != 0
enums:
  category:
    # /usr/share/magic
    0x20090720: ctype
    0x20031114: numeric
    0x20031117: time
    0x20051017: collate
    0x20031111: monetary
    0x20031110: messages
    0x20031113: all
    0x20031112: paper
    0x2003111d: name
    0x2003111c: address
    0x2003111f: telephone
    0x2003111e: measurement
    0x20031119: identification
