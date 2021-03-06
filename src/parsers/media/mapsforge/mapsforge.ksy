meta:
  id: mapsforge
  title: Mapsforge Binary Map File Format
  file-extension: map
  license: CC0-1.0
  endian: be
doc-ref: https://raw.githubusercontent.com/mapsforge/mapsforge/master/docs/Specification-Binary-Map-File.md
seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: magic
        contents: 'mapsforge binary OSM'
      - id: header_size
        type: u4
        doc: size of the file header in bytes (without magic byte)
      - id: version
        type: u4
        doc: version number of the currently used binary file format
      - id: file_size
        type: u8
        doc: The total size of the map file in bytes
      - id: date_of_creation
        type: u8
        doc: date in milliseconds since 01.01.1970
      - id: bounding_box
        size: 16
      - id: tile_size
        type: u2
