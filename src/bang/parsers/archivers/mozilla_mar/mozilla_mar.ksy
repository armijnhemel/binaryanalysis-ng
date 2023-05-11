meta:
  id: mozilla_mar
  title: Mozilla ARchive
  file-extension: mar
  license: CC0-1.0
  encoding: UTF-8
  endian: be
doc: |
  Mozilla ARchive file is Mozilla's own archive format to distribute software updates.
  Test files can be found on Mozilla's FTP site, for example:

  <https://ftp.mozilla.org/pub/firefox/nightly/partials/>
doc-ref: https://wiki.mozilla.org/Software_Update:MAR
seq:
  - id: magic
    contents: "MAR1"
  - id: ofs_index
    -orig-id: OffsetToIndex
    type: u4
  - id: file_size
    -orig-id: FileSize
    type: u8
  - id: num_signatures
    -orig-id: NumSignatures
    type: u4
    valid:
       max: 8
  - id: signatures
    type: signature
    repeat: expr
    repeat-expr: num_signatures
  - id: num_additional_sections
    -orig-id: NumAdditionalSections
    type: u4
  - id: additional_sections
    type: additional_section
    repeat: expr
    repeat-expr: num_additional_sections
instances:
  index:
    pos: ofs_index
    type: mar_index
types:
  signature:
    seq:
      - id: algorithm
        -orig-id: SignatureAlgorithmID
        type: u4
        enum: signature_algorithms
      - id: len_signature
        -orig-id: SignatureSize
        type: u4
        valid:
          max: 2048
      - id: signature
        size: len_signature
  additional_section:
    seq:
      - id: len_block
        type: u4
      - id: block_identifier
        -orig-id: BlockIdentifier
        type: u4
        enum: block_identifiers
      - id: body
        size: len_block - len_block._sizeof - block_identifier._sizeof
        type:
          switch-on: block_identifier
          cases:
            block_identifiers::product_information: product_information_block
  mar_index:
    seq:
      - id: len_index_entries
        -orig-id: IndexSize
        type: u4
      - id: index_entries
        type: index_entries
        size: len_index_entries
  index_entries:
    seq:
      - id: index_entry
        type: index_entry
        repeat: eos
  index_entry:
    seq:
      - id: ofs_content
        -orig-id: OffsetToContent
        type: u4
      - id: len_content
        -orig-id: ContentSize
        type: u4
      - id: flags
        type: u4
        doc: File permission bits (in standard unix-style format).
      - id: file_name
        -orig-id: FileName
        type: strz
    instances:
      content:
        io: _root._io
        pos: ofs_content
        size: len_content
  product_information_block:
    seq:
      - id: mar_channel_name
        -orig-id: MARChannelName
        size: 64
        type: strz
      - id: product_version
        -orig-id: ProductVersion
        size: 32
        type: strz
enums:
  signature_algorithms:
    1: rsa_pkcs1_sha1
    2: rsa_pkcs1_sha384
  block_identifiers:
    1: product_information
