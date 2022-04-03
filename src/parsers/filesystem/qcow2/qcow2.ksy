meta:
  id: qcow2
  title: QEMU QCOW
  license: CC0-1.0
  endian: be
  bit-endian: be
  encoding: UTF-8
doc-ref:
  - https://git.qemu.org/?p=qemu.git;a=blob;f=docs/interop/qcow2.txt;h=0463f761efbb8deadc3e9f429c20bf37dcb4c756;hb=HEAD
seq:
  - id: header_cluster
    type: header
    size: cluster_size
  #- id: clusters
  #  size: cluster_size
  #  repeat: eos
instances:
  cluster_size_bits:
    pos: 0x14
    type: u4
  cluster_size:
    value: 1 << cluster_size_bits
types:
  header:
    seq:
      - id: magic
        contents: ["QFI", 0xfb]
      - id: version
        type: u4
        valid:
          any-of: [2, 3]
      - id: ofs_backing_file
        -orig-id: backing_file_offset
        type: u8
      - id: len_backing_file
        -orig-id: backing_file_size
        type: u4
      - id: cluster_bits
        type: u4
        valid:
          min: 9
      - id: size
        type: u8
      - id: crypt_method
        type: u4
        enum: crypt_methods
        valid:
          any-of:
            - crypt_methods::no_encryption
            - crypt_methods::aes
            - crypt_methods::luks
      - id: num_l1_entries
        -orig-id: l1_size
        type: u4
      - id: ofs_l1_table
        -orig-id: l1_table_offset
        type: u8
        valid:
          expr: ofs_l1_table % _root.cluster_size == 0
      - id: ofs_refcount_table
        -orig-id: refcount_table_offset
        type: u8
        valid:
          expr: ofs_refcount_table % _root.cluster_size == 0
      - id: refcount_table_clusters
        type: u4
      - id: nb_snapshots
        type: u4
      - id: ofs_snapshots
        -orig-id: snapshots_offset
        type: u8
        valid:
          expr: ofs_snapshots % _root.cluster_size == 0
      - id: v3header
        type: v3header
        if: version > 2
      - id: header_extensions
        type: header_extension
        repeat: until
        repeat-until: _.is_end or _io.eof
    instances:
      l1table:
        pos: ofs_l1_table
        type: l1_table(num_l1_entries)
        io: _root._io
        if: ofs_l1_table != 0
      backing_file:
        pos: ofs_backing_file
        size: len_backing_file
        io: _root._io
        type: str
        if: len_backing_file != 0
      snapshot_table:
        pos: ofs_snapshots
        type: snapshot_table(nb_snapshots)
        io: _root._io
      refcount_table:
        pos: ofs_refcount_table
        size: refcount_table_clusters * _root.cluster_size
        type: refcount_table
        io: _root._io
  header_extension:
    seq:
      - id: type
        type: u4
        enum: header_extension_types
        valid:
          any-of:
            - header_extension_types::end
            - header_extension_types::backing_file_format_name_string
            - header_extension_types::feature_name_table
            - header_extension_types::bitmaps_extension
            - header_extension_types::full_disk_encryption_header_pointer
            - header_extension_types::external_data_file_name_string
      - id: len_extension
        type: u4
      - id: data
        size: len_extension
        type:
          switch-on: type
          cases:
            header_extension_types::backing_file_format_name_string: strz
            header_extension_types::feature_name_table: feature_name_table
      - id: padding
        size: -len_extension % 8
    instances:
      is_end:
        value: type == header_extension_types::end

  feature_name_table:
    seq:
      - id: feature_names
        type: feature_name
        repeat: eos
  feature_name:
    seq:
      - id: type
        type: u1
        enum: feature_types
      - id: bit_numner
        type: u1
        valid:
          max: 63
        doc: |
          Bit number within the selected feature bitmap (valid
          values: 0-63)
      - id: name
        size: 46
        type: strz
    enums:
      feature_types:
        0: incompatible
        1: compatible
        2: autoclear
  refcount_table:
    seq:
      - id: entries
        size: 2
        repeat: eos
  l1_table:
    params:
      - id: num_l1_entries
        type: u4
    seq:
      - id: entries
        #type: l1_entry
        size: 2
        repeat: expr
        repeat-expr: num_l1_entries
  l1_entry:
    seq:
      - id: requires_cow
        type: b1
        doc: |
          0 for an L2 table that is unused or requires COW, 1 if its
          refcount is exactly one. This information is only accurate
          in the active L1 table.
      - id: reserved
        type: b7
        valid: 0
      - id: ofs_l2_table
        type: b47
        valid:
          expr: ofs_l2_table % _root.cluster_size == 0
        doc: |
          Bits 9-55 of the offset into the image file at which the L2
          table starts. Must be aligned to a cluster boundary. If the
          offset is 0, the L2 table and all clusters described by this
          L2 table are unallocated.
      - id: reserved2
        type: b9
        valid: 0


  snapshot_table:
    params:
      - id: num_snapshots
        type: u4
    seq:
      - id: entries
        type: snapshot_entry
        repeat: expr
        repeat-expr: num_snapshots
  snapshot_entry:
    seq:
      - id: ofs_l1_table
        type: u8
        valid:
          expr: ofs_l1_table % _root.cluster_size == 0
      - id: num_l1_entries
        type: u4
      - id: len_unique_id
        type: u2
      - id: len_name
        type: u2
      - id: snapshot_time
        type: u4
      - id: snapshot_time_nanoseconds
        type: u4
      - id: snapshot_runtime_nanoseconds
        type: u8
      - id: len_vm_state
        type: u4
      - id: len_extra_data
        type: u4
      - id: len_vm_state2
        type: u8
        if: len_extra_data >= 8
        doc: |
          Size of the VM state in bytes. 0 if no VM
          state is saved. If this field is present,
          the 32-bit value in bytes 32-35 is ignored.
      - id: len_virtual_disk_size
        type: u8
        if: len_extra_data >= 16
      - id: icount_value
        type: u8
        if: len_extra_data >= 24
      - id: unique_id
        size: len_unique_id
        type: str
      - id: snapshot_name
        size: len_name
        type: str
      - id: padding
        size: -(_io.pos) % 8
    instances:
      l1table:
        pos: ofs_l1_table
        type: l1_table(num_l1_entries)
        io: _root._io
        if: ofs_l1_table != 0

  v3header:
    seq:
      - id: incompatible_features
        type: u8
      - id: compatible_features
        type: u8
      - id: autoclear_features
        type: u8
      - id: refcount_order
        type: u4
      - id: len_header
        type: u4
        valid:
          expr: 'len_header >= 104 and len_header % 8 == 0'
enums:
  crypt_methods:
    0: no_encryption
    1: aes
    2: luks
  header_extension_types:
    0x00000000: end
    0xe2792aca: backing_file_format_name_string
    0x6803f857: feature_name_table
    0x23852875: bitmaps_extension
    0x0537be77: full_disk_encryption_header_pointer
    0x44415441: external_data_file_name_string
