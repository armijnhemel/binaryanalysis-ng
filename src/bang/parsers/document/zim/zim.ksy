meta:
  id: zim
  title: Zim
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc: |
  Test files: https://wiki.kiwix.org/wiki/Content_in_all_languages
doc-ref:
  - https://wiki.openzim.org/wiki/ZIM_file_format
  - https://wiki.openzim.org/wiki/ZIM_File_Example
seq:
  - id: header
    type: header
  - id: mimetypes
    type: mimetypes
instances:
  checksum:
    pos: header.checksum
    size: 16
  clusters:
    pos: header.ofs_cluster_pointer
    type: clusters
  titles:
    pos: header.ofs_title_pointer
    type: titles
  url_pointers:
    pos: header.ofs_url_pointer
    type: url_pointers
types:
  raw:
    seq:
      - id: data
        size-eos: true
  header:
    seq:
      - id: magic
        contents: [0x5a, 0x49, 0x4d, 0x04]
      - id: version
        type: version
      - id: uuid
        size: 16
      - id: num_articles
        type: u4
      - id: num_clusters
        type: u4
      - id: ofs_url_pointer
        type: u8
      - id: ofs_title_pointer
        type: u8
      - id: ofs_cluster_pointer
        type: u8
      - id: ofs_mimelist_pointer
        type: u8
      - id: main_page
        type: u4
      - id: layout_page
        type: u4
      - id: checksum
        type: u8
  version:
    seq:
      - id: major
        type: u2
        valid:
          any-of: [5, 6]
      - id: minor
        type: u2
        enum: namespace_type
        valid:
          any-of:
            - namespace_type::old_namespace
            - namespace_type::new_namespace
  clusters:
    seq:
      - id: cluster_offsets
        type: u8
        repeat: expr
        repeat-expr: _root.header.num_clusters
    instances:
      clusters:
        type: cluster(_index)
        repeat: expr
        repeat-expr: _root.header.num_clusters
  cluster:
    params:
      - id: i
        type: u8
    instances:
      cluster:
        pos: _parent.cluster_offsets[i]
        type: cluster_body
        io: _root._io
        size: ofs_end - ofs_start
      ofs_end:
        value: 'i < _parent.cluster_offsets.size  - 1 ?_parent.cluster_offsets[i+1]: _root.header.checksum'
      ofs_start:
        value: _parent.cluster_offsets[i]
  cluster_body:
    seq:
      - id: flag
        type: cluster_flag
      - id: body
        type:
          switch-on: flag.compressed
          cases:
            compression::no_compression: cluster_pointers(flag.offset_size)
            compression::no_compression2: cluster_pointers(flag.offset_size)
            _: raw
  cluster_flag:
    meta:
      bit-endian: be
    seq:
      - id: reserved1
        type: b3
      - id: extended
        type: b1
      - id: compressed
        type: b4
        enum: compression
    instances:
      offset_size:
        value: 'extended ? 8: 4'
  cluster_pointers:
    params:
      - id: offset_size
        type: u4
    seq:
      - id: offsets
        type:
          switch-on: offset_size
          cases:
            4: u4
            8: u8
        repeat: expr
        repeat-expr: num_blobs
    instances:
      first_offset:
        pos: 1
        type:
          switch-on: offset_size
          cases:
            4: u4
            8: u8
      num_blobs:
        value: first_offset / offset_size
        doc: |
          Since the first offset points to the start of the first data,
          the number of offsets can be determined by dividing this offset
          by OFFSET_SIZE.
      blobs:
        type: blobs(_index)
        repeat: expr
        repeat-expr: num_blobs - 1
        doc: |
          The last pointer points to the end of the data area.
          So there is always one more offset than blobs.
    types:
      blobs:
        params:
          - id: index
            type: u4
        instances:
          blob:
            # needs + 1 because the offset does not include
            # the cluster flag
            pos: _parent.offsets[index] + 1
            size: end - start
          end:
            value: _parent.offsets[index+1]
          start:
            value: _parent.offsets[index]
  mimetypes:
    seq:
      - id: mimetype
        type: strz
        repeat: until
        repeat-until: _ == ''
  titles:
    seq:
      - id: title
        type: u4
        repeat: expr
        repeat-expr: _root.header.num_articles
  url_pointers:
    seq:
      - id: url_pointers
        type: u8
        repeat: expr
        repeat-expr: _root.header.num_articles
    instances:
      entries:
        type: url_pointer(_index)
        repeat: expr
        repeat-expr: _root.header.num_articles
  url_pointer:
    params:
      - id: index
        type: u8
    instances:
      entry:
        pos: _root.url_pointers.url_pointers[index]
        type: entry
        io: _root._io
  entry:
    seq:
      - id: mimetype
        type: u2
      - id: body
        type:
          switch-on: mimetype
          cases:
            0xffff: redirect
            _: content
  content:
    seq:
      - id: len_parameter
        type: u1
        valid: 0
        doc: (not used) length of extra parameters (must be 0)
      - id: namespace
        type: u1
        enum: namespace
        doc: defines to which namespace this directory entry belongs
      - id: revision
        type: u4
        doc: |
          (not used) identifies a revision of the contents of this directory
          entry, needed to identify updates or revisions in the original history
          (must be 0)
      - id: cluster_number
        type: u4
        doc: cluster number in which the data of this directory entry is stored
      - id: blob_number
        type: u4
        doc: blob number inside the compressed cluster where the contents are stored
      - id: url
        type: strz
        doc: string with the URL as refered in the URL pointer list
      - id: title
        type: strz
        doc: |
          string with an title as refered in the Title pointer list or empty;
          in case it is empty, the URL is used as title
      - id: parameter
        size: len_parameter
        doc: (not used) extra parameters
  redirect:
    seq:
      - id: len_parameter
        type: u1
        valid: 0
        doc: (not used) length of extra parameters (must be 0)
      - id: namespace
        type: u1
        enum: namespace
        doc: defines to which namespace this directory entry belongs
      - id: revision
        type: u4
        doc: |
          (not used) identifies a revision of the contents of this directory
          entry, needed to identify updates or revisions in the original history
          (must be 0)
      - id: redirect_index
        type: u4
        doc: pointer to the directory entry of the redirect target
      - id: url
        type: strz
        doc: string with the URL as refered in the URL pointer list
      - id: title
        type: strz
        doc: |
          string with an title as refered in the Title pointer list or empty;
          in case it is empty, the URL is used as title
      - id: parameter
        size: len_parameter
        doc: (not used) extra parameters
enums:
  namespace:
    # -
    45:
      id: layout
      doc: layout, eg. the LayoutPage, CSS, favicon.png (48x48), JavaScript and images not related to the articles
    # A
    65:
      id: article
      doc: articles - see Article Format
    # B
    66:
      id: article_meta_data
      doc: article meta data - see Article Format
      doc-ref: https://wiki.openzim.org/w/index.php?title=Article_Format&oldid=1107
    # C
    67:
      id: user_content_entries
      doc: User content entries - see Article Format
    # H
    72:
      id: unknown
      doc: unknown namespace
    # I
    73:
      id: images_files
      doc: images, files - see Image Handling
    # J
    74:
      id: images_text
      doc: images, text - see Image Handling
    # M
    77:
      id: metadata
      doc: ZIM metadata - see Metadata
    # U
    85:
      id: categories_text
      doc: categories, text - see Category Handling
    # V
    86:
      id: categories_article_list
      doc: categories, article list - see Category Handling
    # W
    87:
      id: categories_per_article_or_well_known_entries
      doc: |
        old namespace: categories per article, category list - see Category Handling
        new namespace: Well know entries (MainPage, Favicon) - see Well known entries
    # X
    88:
      id: search_indexes
    # Z
    90:
      id: xapian_indexes
      doc: |
        The documentation omits 'Z', which can be found in
        libzim/src/search.cpp and is related to Xapian indexes.
  namespace_type:
    0: old_namespace
    1: new_namespace
  compression:
    0: no_compression
    1: no_compression2
    2: zlib
    3: bzip2
    4: xz
    5: zstd
