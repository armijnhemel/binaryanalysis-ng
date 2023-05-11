meta:
  id: chm
  title: Windows Compiled HTML help
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc-ref:
  - http://www.russotto.net/chm/chmformat.html
  - https://www.nongnu.org/chmspec/latest/
seq:
  - id: header
    type: header
  - id: header_section_table
    size: header.len_header - header._sizeof
    type: header_section_table
instances:
  filesize:
    value: header0.len_file
  header0:
    pos: header_section_table.ofs_header0
    size: header_section_table.len_header0
    type: header0
  header1:
    pos: header_section_table.ofs_header1
    size: header_section_table.len_header1
    type: header1
  content:
    pos: header_section_table.ofs_content0
    size: filesize - header_section_table.ofs_content0
types:
  header:
    seq:
      - id: magic
        contents: "ITSF"
      - id: version
        type: u4
        valid: 3
      - id: len_header
        type: u4
        doc: Total header length, including header section table and following data.
      - id: unknown1
        type: u4
        valid: 1
      - id: timestamp
        type: u4
      - id: windows_language_id
        type: u4
      - id: guid1
        size: 16
      - id: guid2
        size: 16
  header_section_table:
    seq:
      - id: ofs_header0
        type: u8
      - id: len_header0
        type: u8
      - id: ofs_header1
        type: u8
      - id: len_header1
        type: u8
      - id: ofs_content0
        type: u8
  header0:
    seq:
      - id: unknown1
        type: u4
        valid: 0x1fe
      - id: unknown2
        type: u4
        valid: 0
      - id: len_file
        type: u8
      - id: unknown3
        type: u4
        valid: 0
      - id: unknown4
        type: u4
        valid: 0
  header1:
    seq:
      - id: magic
        contents: 'ITSP'
      - id: version
        type: u4
        valid: 1
      - id: len_directory_header
        type: u4
      - id: unknown1
        type: u4
        valid: 0x0a
      - id: len_directory_chunk
        type: u4
        valid: 4096
      - id: density
        type: u4
      - id: index_tree_depth
        type: u4
        valid:
          any-of: [1, 2]
      - id: root_index_chunk_number
        type: s4
      - id: first_pmgl_chunk
        type: u4
      - id: last_pmgl_chunk
        type: u4
      - id: unknown2
        type: s4
        valid: -1
      - id: num_directory_chunks
        type: u4
      - id: windows_language_id
        type: u4
      - id: guid
        size: 16
      - id: len_directory_header2
        type: u4
        valid: 0x54
      - id: unknown3
        type: s4
        valid: -1
      - id: unknown4
        type: s4
        valid: -1
      - id: unknown5
        type: s4
        valid: -1
      - id: directory_chunks
        size: len_directory_chunk
        type: directory_chunk
        repeat: expr
        repeat-expr: num_directory_chunks
  directory_chunk:
    seq:
      - id: magic
        type: u4
        enum: chunk_magic
      - id: directory_chunk_body
        type:
          switch-on: magic
          cases:
            #chunk_magic::index: index
            chunk_magic::listing: listing
  listing:
    seq:
      - id: len_quickref
        type: u4
      - id: unknown1
        type: u4
        valid: 0
      - id: previous_chunk
        type: s4
      - id: next_chunk
        type: s4
      - id: entries_and_quickref
        type: entries_and_quickref
        size-eos: true
  entries_and_quickref:
    seq:
      - id: entry_quickref
        size-eos: true
enums:
  chunk_magic:
    0x49474d50:
      id: index 
      doc: PMGI
    0x4c474d50:
      id: listing
      doc: PMGL
