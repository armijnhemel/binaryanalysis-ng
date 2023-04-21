meta:
  id: stone
  title: SerpentOS Stone
  license: Zlib
  encoding: UTF-8
  endian: be
doc-ref: <https://github.com/serpent-os/libmoss/blob/841a6d67/source/moss/format/binary/archive_header.d>
seq:
  - id: header
    type: header
    size: 32
  - id: payloads
    type: payload
    repeat: expr
    repeat-expr: header.num_payloads
types:
  header:
    seq:
      - id: signature
        contents: [0, 0x6d, 0x6f, 0x73]
      - id: num_payloads
        type: u2
      - id: integrity_check
        contents: [0, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0, 7]
      - id: type
        type: u1
        enum: file_types
      - id: version
        type: u4
  payload:
    -webide-representation: "{type}"
    seq:
      - id: len_data
        type: u8
      - id: len_usable_data
        type: u8
        # use len_uncompressed instead?
      - id: xxhash3_64
        size: 8
      - id: num_records
        type: u4
      - id: payload_version
        type: u2
      - id: type
        type: u1
        enum: payload_type
      - id: compression
        type: u1
        enum: compression
      - id: data
        size: len_data
  meta_records:
    seq:
      - id: records
        type: meta_record
        repeat: eos
  meta_record:
    -webide-representation: "{record_tag}"
    seq:
      - id: len_record
        type: u4
      - id: record_tag
        type: u2
        enum: record_tags
      - id: record_type
        type: u1
        enum: record_types
      - id: reserved
        size: 1
      - id: record
        size: len_record
        type:
          switch-on: record_type
          cases:
            record_types::int8: s1
            record_types::uint8: u1
            record_types::int16: s2
            record_types::uint16: u2
            record_types::int32: s4
            record_types::uint32: u4
            record_types::int64: s8
            record_types::uint64: u8
            record_types::string: strz
  layout_entries:
    seq:
      - id: entries
        type: layout_entry
        repeat: eos
  layout_entry:
    -webide-representation: "{file_type}"
    seq:
      - id: uid
        type: u4
      - id: gid
        type: u4
      - id: mode
        type: u4
      - id: tag
        type: u4
      - id: len_source
        type: u2
      - id: len_target
        type: u2
      - id: file_type
        type: u1
        enum: file_type
      - id: padding
        size: 11
      - id: source
        size: len_source
      - id: target
        size: len_target
        type: strz
    enums:
      file_type:
        0: unknown
        1: regular
        2: symlink
        3: directory
        4: character_device
        5: block_device
        6: fifo
        7: socket
  index_entries:
    seq:
      - id: entries
        type: index_entry
        repeat: eos
  index_entry:
    seq:
      - id: ofs_start
        type: u8
      - id: ofs_end
        type: u8
      - id: hash_digest
        size: 16
    instances:
      len_file:
        value: ofs_end - ofs_start
enums:
  file_types:
    0: unknown
    1: binary
    2: delta
    3: repository
    4: build_manifest
  compression:
    0: unknown
    1: no_compression
    2: zstd
  payload_type:
    0: unknown
    1: meta
    2: content
    3: layout
    4: index
    5: attributes
    6: dumb
  record_tags:
    0: unknown
    1: name
    2: architecture
    3: version
    4: summary
    5: description
    6: homepage
    7: source_id
    8: depends
    9: provides
    10: conflicts
    11: release
    12: license
    13: build_release
    14: package_uri
    15: package_hash
    16: package_size
    17: build_depends
    18: source_uri
    19: source_path
    20: source_ref
  record_types:
    0: unknown
    1: int8
    2: uint8
    3: int16
    4: uint16
    5: int32
    6: uint32
    7: int64
    8: uint64
    9: string
    10: dependency
    11: provider
