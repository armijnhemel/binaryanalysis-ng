meta:
  id: sepolicy
  title: SELinux policy file
  file-extension: bin
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://github.com/SELinuxProject/selinux/blob/b550c0e/libsepol/src/write.c#L2122
seq:
  - id: magic
    size: 4
    contents: [0x8c, 0xff, 0x7c, 0xf9]
    # SELINUX_MAGIC / POLICYDB_MAGIC
  - id: len_policydb_string
    type: u4
  - id: policydb_string
    type: strz
    size: len_policydb_string
  - id: policy_version
    type: u4
    valid:
      min: 24
    # don't bother with POLICYDB_VERSION_PERMISSIVE right now
  - id: config
    type: u4
  - id: num_symbols
    type: u4
  - id: num_ocons
    type: u4
  - id: symbols
    type: symbol
    repeat: expr
    repeat-expr: num_symbols
  - id: avtab
    type: avtab
types:
  symbol:
    seq:
      - id: nprim
        type: u4
      - id: nel
        type: u4
  avtab:
    seq:
      - id: source_type
        type: u2
      - id: target_type
        type: u2
      - id: target_class
        type: u2
      - id: specified
        type: u2
