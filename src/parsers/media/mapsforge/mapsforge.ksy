meta:
  id: mapsforge
  title: Mapsforge Binary Map File Format
  file-extension: map
  license: CC0-1.0
  endian: be
  encoding: UTF-8
  imports:
    - /common/vlq_base128_le
doc-ref: https://raw.githubusercontent.com/mapsforge/mapsforge/master/docs/Specification-Binary-Map-File.md
doc: |
  Incomplete and probably incorrect grammar for mapsforge files. The
  incorrectness is related to the use of leb128 (vlq_base128) which
  according to the mapsforge docs isn't true for signed values.
seq:
  - id: preheader
    type: preheader
  - id: header
    type: header
    size: preheader.len_header
  - id: maps_data
    size: header.len_file - preheader.len_header - preheader._sizeof
types:
  preheader:
    seq:
      - id: magic
        contents: 'mapsforge binary OSM'
      - id: len_header
        type: u4
        doc: size of the file header in bytes (without magic byte)
  header:
    seq:
      - id: version
        type: u4
        doc: version number of the currently used binary file format
      - id: len_file
        type: u8
        doc: The total size of the map file in bytes
      - id: creation_data
        type: u8
        doc: date in milliseconds since 01.01.1970
      - id: bounding_box
        type: bounding_box
      - id: tile_size
        type: u2
      - id: projection
        type: mapsforge_string
      - id: flags
        type: u1
      - id: map_start_position
        type: geo_coordinate
        if: has_map_start_position_field
      - id: start_zoom_level
        type: u1
        if: has_start_zoom_level_field
      - id: language_preference
        type: mapsforge_string
        if: has_language_preference_field
      - id: comment
        type: mapsforge_string
        if: has_comment_field
      - id: created_by
        type: mapsforge_string
        if: has_created_by_field
      - id: poi_tags
        type: tags
      - id: way_tags
        type: tags
      - id: num_zoom_intervals
        type: u1
      - id: zoom_intervals
        type: zoom_interval
        repeat: expr
        repeat-expr: num_zoom_intervals
    instances:
      has_debug_information:
        value: flags & 0x80 == 0x80
      has_map_start_position_field:
        value: flags & 0x40 == 0x40
      has_start_zoom_level_field:
        value: flags & 0x20 == 0x20
      has_language_preference_field:
        value: flags & 0x10 == 0x10
      has_comment_field:
        value: flags & 0x08 == 0x08
      has_created_by_field:
        value: flags & 0x04 == 0x04
  zoom_interval:
    seq:
      - id: base_zoom_level
        type: u1
      - id: minimal_zoom_level
        type: u1
      - id: maximal_zoom_level
        type: u1
      - id: ofs_sub_file
        type: u8
        valid:
          min: _root.preheader.len_header
          max: _root.header.len_file
        doc: absolute start position of the sub file
      - id: len_sub_file
        type: u8
        valid:
          max: _root.header.len_file - ofs_sub_file
  tags:
    seq:
      - id: num_tags
        type: u2
      - id: tags
        type: mapsforge_string
        repeat: expr
        repeat-expr: num_tags
  geo_coordinate:
    seq:
      - id: lat
        type: u4
      - id: lon
        type: u4
  bounding_box:
    seq:
      - id: min_lat
        type: u4
      - id: min_lon
        type: u4
      - id: max_lat
        type: u4
      - id: max_lon
        type: u4
  mapsforge_string:
    seq:
      - id: len_string
        type: vlq_base128_le
      - id: data
        size: len_string.value
        type: str
