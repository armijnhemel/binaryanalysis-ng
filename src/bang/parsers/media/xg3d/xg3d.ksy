meta:
  id: xg3d
  title: 3D Studio Max XG Exporter files
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc: |
  a proprietary file format from 3D Studio Max. There is not
  much to extract, but at least the size of the file can be verified.
  This analysis was based on just a few samples found inside the
  firmware of an Android phone made by LG Electronics.

  Test file: LGF320S-V21j-MAR-15-2014.tot
seq:
  - id: header
    type: header
  - id: data
    size: header.len_file - header._sizeof
types:
  header:
    seq:
      - id: magic
        contents: 'XG3D'
      - id: unknown
        size: 25
      - id: len_file
        type: u4
        # u4? u2?
      - id: len_file_2
        type: u4
        # u4? u2?
      - id: tool_name
        type: strz
        size: 34
