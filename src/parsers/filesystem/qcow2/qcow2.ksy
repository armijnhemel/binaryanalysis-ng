meta:
  id: qcow2
  title: QEMU QCOW
  license: CC0-1.0
  endian: be
  encoding: ASCII
doc-ref:
  - https://git.qemu.org/?p=qemu.git;a=blob;f=docs/interop/qcow2.txt;h=0463f761efbb8deadc3e9f429c20bf37dcb4c756;hb=HEAD
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
  - id: len_l1
    -orig-id: l1_size
    type: u4
  - id: ofs_l1_table
    -orig-id: l1_table_offset
    type: u8
  - id: ofs_refcount_table
    -orig-id: refcount_table_offset
    type: u8
  - id: refcount_table_clusters
    type: u4
  - id: nb_snapshots
    type: u4
  - id: ofs_snapshots
    -orig-id: snapshots_offset
    type: u8
  - id: v3header
    type: v3header
    if: version > 2
types:
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
instances:
  l1table:
    pos: ofs_l1_table
    size: len_l1
    if: ofs_l1_table != 0
enums:
  crypt_methods:
    0: no_encryption
    1: aes
    2: luks
