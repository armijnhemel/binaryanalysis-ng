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
  urls:
    pos: header.ofs_url_pointer
    type: urls
types:
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
      cluster:
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
  cluster_body:
    seq:
      - id: flag
        type: cluster_flag
      - id: body
        type: u4
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
  urls:
    seq:
      - id: url
        type: u8
        repeat: expr
        repeat-expr: _root.header.num_articles
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
    # C
    67:
      id: user_content_entries
      doc: User content entries - see Article Format
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
