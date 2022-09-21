meta:
  id: wim
  title: Windows Imaging Format
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
seq:
  - id: preheader
    type: preheader
  - id: header
    type: header
    size: preheader.len_header - preheader._sizeof
types:
  preheader:
    seq:
      - id: magic
        -orig-id: ImageTag
        contents: "MSWIM\0\0\0"
      - id: len_header
        -orig-id: cbSize
        type: u4
        valid:
          min: 208
  header:
    seq:
      - id: version
        -orig-id: dwVersion
        type: u4
      - id: flags
        -orig-id: dwFlags
        type: u4
      - id: len_data
        -orig-id: dwCompressionSize
        type: u4
        doc: Size of the compressed .wim file in bytes.
      - id: guid
        -orig-id: gWIMGuid
        size: 16
      - id: part_number
        type: u2
        doc: |
          The part number of the current .wim file in a spanned set.
          This value is 1, unless the data of the .wim file was split
          into multiple parts (.swm).
      - id: total_parts
        type: u2
      - id: image_count
        type: u4
        doc: The number of images contained in the .wim file.
      - id: ofs_table
        type: reshdr_disk_short
      - id: xml_metadata
        type: reshdr_disk_short
      - id: boot_metadata
        type: reshdr_disk_short
      - id: boot_index
        type: u4
      - id: integrity
        type: reshdr_disk_short
      - id: unused
        size: 60
    instances:
      xml:
        pos: xml_metadata.offset
        size: xml_metadata.size
        io: _root._io

  reshdr_disk_short:
    seq:
      - id: size_and_flags
        type: u8
      - id: offset
        -orig-id: liOffset
        type: u8
      - id: uncompressed_size
        -orig-id: liOriginalSize
        type: u8
    instances:
      size:
        value: size_and_flags & 72057594037927935
      flags:
        value: size_and_flags >> 56
