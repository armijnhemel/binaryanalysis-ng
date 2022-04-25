meta:
  id: avb0
  title: Android Verified Boot
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: be
doc-ref:
  - https://android.googlesource.com/platform/external/avb/+/de53827b226bccef7407e4c253b0152e8d9f8e04/libavb/avb_vbmeta_image.h
  - https://android.googlesource.com/platform/external/avb/+/de53827b226bccef7407e4c253b0152e8d9f8e04/libavb/avb_crypto.h
seq:
  - id: header
    type: header
    size: 256
  - id: authentication_data
    type: authentication_data
    size: header.len_authentication_block
  - id: auxiliary_data
    type: auxiliary_data
    size: header.len_auxiliary_block
  - id: padding
    type: padding_byte
    repeat: expr
    repeat-expr: (- _io.pos) % block_size
  - id: blocks
    type: block
    size: block_size
    repeat: until
    repeat-until: _.footer.is_footer or _io.eof or (not _.footer.is_footer and not _.footer.is_padding)
instances:
  block_size:
    value: 4096
  footer_size:
    value: 64
types:
  padding_block:
    seq:
      - id: padding
        contents: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  padding_byte:
    seq:
      - id: padding
        contents: [0x00]
  block:
    seq:
      - id: padding
        type: padding_block
        repeat: expr
        repeat-expr: (_root.block_size - _root.footer_size) / 64
      - id: footer
        type: footer_or_padding
        size-eos: true
  footer_or_padding:
    seq:
      - id: footer
        type: footer
        if: is_footer
      - id: padding
        type: padding_byte
        repeat: eos
        if: is_padding
    instances:
      magic:
        pos: 0
        size: 4
      is_footer:
        value: magic == [0x41, 0x56, 0x42, 0x66]   # '"AVBf"'
      is_padding:
        value: magic == [0x00, 0x00, 0x00, 0x00]
  header:
    seq:
      - id: magic
        contents: "AVB0"
      - id: major_version
        type: u4
      - id: minor_version
        type: u4
      - id: len_authentication_block
        type: u8
      - id: len_auxiliary_block
        type: u8
      - id: algorithm
        type: u4
        enum: encryption
        valid:
          any-of:
            - encryption::no_encryption
            - encryption::sha256_rsa2048
            - encryption::sha256_rsa4096
            - encryption::sha256_rsa8192
            - encryption::sha512_rsa2048
            - encryption::sha512_rsa4096
            - encryption::sha512_rsa8192
      - id: ofs_hash
        type: u8
      - id: len_hash
        type: u8
      - id: ofs_signature
        type: u8
      - id: len_signature
        type: u8
      - id: ofs_public_key
        type: u8
      - id: len_public_key
        type: u8
      - id: ofs_public_key_metadata
        type: u8
      - id: len_public_key_metadata
        type: u8
      - id: ofs_descriptors
        type: u8
      - id: len_descriptors
        type: u8
      - id: rollback_index
        type: u8
      - id: flags
        type: u4
      - id: padding1
        contents: [0x00, 0x00, 0x00, 0x00]
      - id: release_string
        type: strz
        size: 48
      - id: padding2
        type: padding_byte
        repeat: expr
        repeat-expr: 80
  footer:
    seq:
      - id: magic
        contents: "AVBf"
      - id: major_version
        type: u4
      - id: minor_version
        type: u4
      - id: original_image_size
        type: u8
        doc: The original size of the image on the partition.
      - id: vbmeta_offset
        type: u8
        doc: The offset of the |AvbVBMetaImageHeader| struct.
      - id: vbmeta_size
        type: u8
        doc: The size of the vbmeta block (header + auth + aux blocks).
      - id: reserved
        size: 28
  authentication_data:
    instances:
      hash:
        pos: _root.header.ofs_hash
        size: _root.header.len_hash
      signature:
        pos: _root.header.ofs_signature
        size: _root.header.len_signature
  auxiliary_data:
    instances:
      public_key:
        pos: _root.header.ofs_public_key
        size: _root.header.len_public_key
      public_key_metadata:
        pos: _root.header.ofs_public_key_metadata
        size: _root.header.len_public_key_metadata
      descriptors:
        pos: _root.header.ofs_descriptors
        size: _root.header.len_descriptors
        type: descriptors
  descriptors:
    seq:
      - id: descriptor
        type: descriptor
        repeat: eos
  descriptor:
    -webide-representation: '{tag}'
    seq:
      - id: tag
        type: u8
        enum: descriptor_tags
      - id: len_descriptor_data
        type: u8
      - id: descriptor_data
        size: len_descriptor_data
        type:
          switch-on: tag
          cases:
            descriptor_tags::property: property_descriptor
            descriptor_tags::hashtree: hashtree
            descriptor_tags::hash: hash
            descriptor_tags::kernel_cmdline: kernel_cmdline
            descriptor_tags::chain_partition: chain_partition
      - id: padding
        size: (- _io.pos) % 8
  property_descriptor:
    seq:
      - id: len_key_data
        type: u8
      - id: len_value_data
        type: u8
      - id: key
        type: strz
        size: len_key_data
      - id: null_byte1
        contents: [0x00]
      - id: value
        type: strz
        size: len_value_data
      - id: null_byte2
        contents: [0x00]
      - id: padding
        size: (- _io.pos) % 8
  hashtree:
    seq:
      - id: dm_verity_version
        type: u4
      - id: image_size
        type: u8
      - id: tree_offset
        type: u8
      - id: tree_size
        type: u8
      - id: data_block_size
        type: u4
      - id: hash_block_size
        type: u4
      - id: fec_num_roots
        type: u4
      - id: fec_offset
        type: u8
      - id: fec_size
        type: u8
      - id: hash_algorithm
        size: 32
        type: strz
      - id: len_partition_name
        type: u4
      - id: len_salt
        type: u4
      - id: len_root_digest
        type: u4
      - id: flags
        type: u4
      - id: reserved
        size: 60
      - id: partition_name
        type: str
        size: len_partition_name
      - id: salt
        size: len_salt
      - id: root_digest
        size: len_root_digest
  hash:
    seq:
      - id: image_size
        type: u8
      - id: hash_algorithm
        size: 32
        type: strz
      - id: len_partition_name
        type: u4
      - id: len_salt
        type: u4
      - id: len_digest
        type: u4
      - id: flags
        type: u4
      - id: reserved
        size: 60
      - id: partition_name
        type: str
        size: len_partition_name
      - id: salt
        size: len_salt
      - id: digest
        size: len_digest
  kernel_cmdline:
    seq:
      - id: flags
        type: u4
      - id: len_kernel_cmdline
        type: u4
      - id: kernel_cmdline
        type: str
        size: len_kernel_cmdline
  chain_partition:
    seq:
      - id: rollback_index_location
        type: u4
      - id: len_partition_name
        type: u4
      - id: len_public_key
        type: u4
      - id: reserved
        size: 64
      - id: partition_name
        type: str
        size: len_partition_name
      - id: public_key
        size: len_public_key
enums:
  encryption:
    0: no_encryption
    1: sha256_rsa2048
    2: sha256_rsa4096
    3: sha256_rsa8192
    4: sha512_rsa2048
    5: sha512_rsa4096
    6: sha512_rsa8192
  descriptor_tags:
    0: property
    1: hashtree
    2: hash
    3: kernel_cmdline
    4: chain_partition
