meta:
  id: mobi
  title: MOBI
  license: CC0-1.0
  encoding: UTF-8
  endian: be
doc-ref:
  - https://wiki.mobileread.com/wiki/MOBI
  - https://fossies.org/linux/calibre/format_docs/pdb/mobi.txt
seq:
  - id: header
    type: palm_database

types:
  palm_database:
    seq:
      - id: name
        size: 32
        type: strz
      - id: attributes
        type: u2
      - id: version
        type: u2
      - id: creation_date
        type: u4
        doc: No. of seconds since start of January 1, 1904.
      - id: modification_date
        type: u4
        doc: No. of seconds since start of January 1, 1904.
      - id: last_backup_date
        type: u4
        doc: No. of seconds since start of January 1, 1904.
      - id: modification_number
        type: u4
      - id: ofs_app_info_id
        type: u4
        doc: offset to start of Application Info (if present) or null
      - id: ofs_sort_info_id
        type: u4
        doc: offset to start of Sort Info (if present) or null
      - id: type
        contents: 'BOOK'
      - id: creator
        contents: 'MOBI'
      - id: unique_id_seed
        type: u4
      - id: next_record_list_id
        type: u4
        doc: Only used when in-memory on Palm OS. Always set to zero in stored files.
      - id: num_records
        type: u2
      - id: first_record
        type: record(true)
      - id: records
        type: record(false)
        repeat: expr
        repeat-expr: num_records - 1
  record:
    params:
      - id: first
        type: bool
    seq:
      - id: ofs_record_data
        type: u4
        doc: the offset of record n from the start of the PDB of this record
      - id: attributes
        type: u1
      - id: unique_id
        size: 3
    instances:
      record:
        pos: ofs_record_data
        type:
          switch-on: first
          cases:
            true: mobi_record
            false: u1
  mobi_record:
    seq:
      - id: compression
        type: u2
        enum: compression
      - id: unused
        type: u2
        valid: 0
      - id: len_text
        type: u4
        doc: Uncompressed length of the entire text of the book
      - id: num_records
        type: u2
        doc: Number of PDB records used for the text of the book.
      - id: len_record
        type: u2
        valid: 4096
        doc: Maximum size of each record containing text, always 4096
      - id: encryption
        type: u2
        enum: encryption
      - id: unknown
        size: 2
      - id: mobi_header
        type: mobi_header
      - id: ext_header
        type: exth
        if: mobi_header.rest_of_header.has_exth
  mobi_header:
    seq:
      - id: magic
        contents: 'MOBI'
      - id: len_header
        type: u4
        doc: the length of the MOBI header, including the previous 4 bytes
      - id: rest_of_header
        type: rest_of_mobi_header
        size: len_header - magic._sizeof - len_header._sizeof
  rest_of_mobi_header:
    seq:
      - id: mobi_type
        type: u4
        enum: mobi_type
      - id: encoding
        type: u4
        enum: encoding
      - id: unique_id
        size: 4
      - id: file_version
        type: u4
      - id: ortographic_index
        type: u4
        doc: Section number of orthographic meta index. 0xFFFFFFFF if index is not available.
      - id: inflection_index
        type: u4
        doc: Section number of inflection meta index. 0xFFFFFFFF if index is not available.
      - id: index_names
        type: u4
      - id: index_keys
        type: u4
      - id: extra_index_0
        type: u4
      - id: extra_index_1
        type: u4
      - id: extra_index_2
        type: u4
      - id: extra_index_3
        type: u4
      - id: extra_index_4
        type: u4
      - id: extra_index_5
        type: u4
      - id: first_non_book_index
        type: u4
      - id: ofs_full_name
        type: u4
        doc: Offset in record 0 (not from start of file) of the full name of the book
      - id: len_full_name
        type: u4
        doc: Length in bytes of the full name of the book
      - id: book_locale_code
        type: u4
      - id: input_language
        type: u4
      - id: output_language
        type: u4
      - id: minimum_version
        type: u4
      - id: first_image_index
        type: u4
        doc: First record number (starting with 0) that contains an image. Image records should be sequential.
      - id: ofs_huffman_record
        type: u4
      - id: num_huffman_records
        type: u4
      - id: ofs_huffman_table
        type: u4
      - id: len_huffman_table
        type: u4
      - id: exth_flags
        type: u4
      - id: unknown
        size: 32
      - id: unknown2
        type: u4
        #valid: 4294967295
      - id: ofs_drm
        type: u4
      - id: num_drm
        type: u4
      - id: len_drm
        type: u4
      - id: drm_flags
        type: u4
      - id: unknown3
        type: u8
        valid: 0
      - id: first_content_record
        type: u2
      - id: last_content_record
        type: u2
      - id: unknown4
        type: u4
      - id: fcis_record
        type: u4
      - id: unknown5
        type: u4
      - id: flis_record
        type: u4
      - id: unknown6
        type: u4
      - id: unknown7
        size: 8
      - id: unknown8
        type: u4
      - id: num_first_compilation_data_sections
        type: u4
      - id: num_compilation_data_sections
        type: u4
      - id: unknown9
        type: u4
      - id: extra_record_data_flags
        type: u4
      - id: ofs_indx_record
        type: u4
      - id: unknown10
        type: u4
        if: _parent.len_header == 256
      - id: unknown11
        type: u4
        if: _parent.len_header == 256
      - id: unknown12
        type: u4
        if: _parent.len_header == 256
      - id: unknown13
        type: u4
        if: _parent.len_header == 256
      - id: unknown14
        type: u4
        if: _parent.len_header == 256
      - id: unknown15
        type: u4
        if: _parent.len_header == 256
    instances:
      has_exth:
        value: exth_flags & 0x40 == 0x40
      #full_name:
      #  pos: ofs_full_name
      #  size: len_full_name
      #  type: str
  exth:
    seq:
      - id: magic
        contents: 'EXTH'
      - id: len_header
        type: u4
        doc: |
          the length of the EXTH header, including the previous 4 bytes - but
          not including the final padding.
      - id: num_records
        type: u4
        doc: |
          The number of records in the EXTH header. the rest of the EXTH header
          consists of repeated EXTH records to the end of the EXTH length.
      - id: records
        type: exth_record
        repeat: expr
        repeat-expr: num_records
      - id: padding
        size: (- _io.pos) % 4
        doc: |
          Null bytes to pad the EXTH header to a multiple of four bytes
          (none if the header is already a multiple of four). This padding is
          not included in the EXTH header length. 

  exth_record:
    seq:
      - id: type
        type: u4
        enum: exth_record_type
      - id: len_record
        type: u4
        doc: |
          length of EXTH record = L , including the 8 bytes in the type
          and length fields
      - id: data
        size: len_record - len_record._sizeof - type._sizeof
        type:
          switch-on: type
          cases:
            exth_record_type::author: str
            exth_record_type::publisher: str
            exth_record_type::imprint: str
            exth_record_type::description: str
            exth_record_type::isbn: str
            exth_record_type::subject: str
            exth_record_type::publishing_date: str
            exth_record_type::review: str
            exth_record_type::contributor: str
            exth_record_type::rights: str
            exth_record_type::subject_code: str
            exth_record_type::type: str
            exth_record_type::source: str
            exth_record_type::asin: str
            exth_record_type::version_number: str
            exth_record_type::sample: u4
            exth_record_type::start_reading: u4
            exth_record_type::adult: str
            exth_record_type::retail_price: str
            exth_record_type::retail_price_currency: str
            exth_record_type::kf8_boundary: u4
            exth_record_type::fixed_layout: str
            exth_record_type::book_type: str
            exth_record_type::orientation_lock: str

            exth_record_type::metadata_resource_uri: str
            exth_record_type::kf8_unknown_count: u4

            exth_record_type::cover_offset: u4
            exth_record_type::thumb_offset: u4
            exth_record_type::has_fake_cover: u4
            exth_record_type::creator_software: u4
            exth_record_type::creator_major_version: u4
            exth_record_type::creator_minor_version: u4
            exth_record_type::creator_build_number: u4

            exth_record_type::cde_type: str
            exth_record_type::updated_title: str
            exth_record_type::language: str
            exth_record_type::primary_writing_mode: str
enums:
  compression:
    1: no_compression
    2: palmdoc
    17480: huff_cdic
  encryption:
    0: no_encryption
    1: old_mobipocket
    2: mobipocket
  mobi_type:
    2: mobipocket_book
    3: palmdoc_book
    4: audio
    232: mobipocket_kindlegen12
    248: kf8
    257: news
    258: news_feed
    259: news_magazine
    513: pics
    514: word
    515: xls
    516: ppt
    517: text
    518: html
  encoding:
    1252: cp1252
    65001: utf8
  exth_record_type:
    # https://github.com/kovidgoyal/calibre/blob/master/src/calibre/ebooks/mobi/writer8/exth.py
    # https://github.com/kovidgoyal/calibre/blob/master/src/calibre/ebooks/mobi/debug/headers.py
    1: drm_server_id
    2: drm_commerce_id
    3: drm_ebookbase_book_id
    100: author
    101: publisher
    102: imprint
    103: description
    104: isbn
    105: subject
    106: publishing_date
    107: review
    108: contributor
    109: rights
    110: subject_code
    111: type
    112: source
    113: asin
    114: version_number
    115: sample
    116: start_reading
    117: adult
    118: retail_price
    119: retail_price_currency
    121: kf8_boundary
    122: fixed_layout
    123: book_type
    124: orientation_lock
    125: count_of_resources
    126: original_resolution
    127: zero_gutter
    128: zero_margin
    129: metadata_resource_uri
    131: kf8_unknown_count
    132: unknown
    200: dictionary_short_name
    201: cover_offset
    202: thumb_offset
    203: has_fake_cover
    204: creator_software
    205: creator_major_version
    206: creator_minor_version
    207: creator_build_number
    208: watermark
    209: tamper_proof_keys
    300: font_signature
    401: clipping_limit
    402: publisher_limit
    403: unknown2
    404: tts_flag
    405: unknown3
    406: expiration_date
    407: unknown4
    450: unknown5
    451: unknown6
    452: unknown7
    453: unknown8
    501: cde_type
    502: last_update_time
    503: updated_title
    504: asin_5xx
    508: unknown_title
    517: unknown_creator
    522: unknown_publisher
    524: language
    525: primary_writing_mode
    527: page_progression_direction
    528: override_kindle_fonts
    534: input_source_type
    535: kindlegen_build_rev_number
    536: container_info
    538: container_resolution
    539: container_mimetype
    542: unknown9
    543: container_id
    547: in_memory
