meta:
  id: java_keystore
  title: Java Keystore
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: be
doc-ref:
  - https://github.com/openjdk-mirror/jdk7u-jdk/blob/master/src/share/classes/sun/security/provider/JavaKeyStore.java
  - https://github.com/kurtbrose/pyjks
seq:
  - id: magic
    contents: [0xfe, 0xed, 0xfe, 0xed]
  - id: version
    type: u4
    #valid:
      #any-of: [1, 2]
    valid: 2
    doc: only process version 2 for now
  - id: num_key_entries
    type: u4
    valid:
      max: _root._io.size
  - id: key_entries
    type: key_entry
    repeat: expr
    repeat-expr: num_key_entries
  - id: sha1
    size: 20
types:
  key_entry:
    seq:
      - id: tag
        type: u4
        valid:
          any-of: [1, 2]
      - id: len_alias
        type: u2
      - id: alias
        type: str
        size: len_alias
      - id: timestamp
        type: u8
      - id: key_entry_data
        type:
          switch-on: tag
          cases:
            1: key_entry_data_1
            2: key_entry_data_2
  key_entry_data_1:
    seq:
      - id: len_private_key
        type: u4
      - id: private_key
        size: len_private_key
      - id: num_certificates
        type: u4
      - id: certificates
        type: certificate
        repeat: expr
        repeat-expr: num_certificates
  key_entry_data_2:
    seq:
      - id: certificate
        type: certificate
  certificate:
    seq:
      - id: len_name
        type: u2
      - id: name
        type: str
        size: len_name
      - id: len_certificate
        type: u4
      - id: certificate
        size: len_certificate
