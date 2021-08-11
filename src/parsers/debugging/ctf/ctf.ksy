meta:
  id: ctf
  title: Compact C Type Format
  license: BSD
  endian: le
doc-ref: https://www.freebsd.org/cgi/man.cgi?query=ctf&sektion=5&manpath=freebsd-release-ports
seq:
  - id: preamble
    type: preamble
  - id: header
    type: header
instances:
  labels:
    pos: header.ofs_label_section + preamble._sizeof + header._sizeof
    size: header.ofs_object_section - header.ofs_label_section
  objects:
    pos: header.ofs_object_section + preamble._sizeof + header._sizeof
    size: header.ofs_function_section - header.ofs_object_section
  functions:
    pos: header.ofs_function_section + preamble._sizeof + header._sizeof
    size: header.ofs_type_section - header.ofs_function_section
  types:
    pos: header.ofs_type_section + preamble._sizeof + header._sizeof
    size: header.ofs_string_section - header.ofs_type_section
  strings:
    pos: header.ofs_string_section + preamble._sizeof + header._sizeof
    size: header.len_string_section
    
types:
  preamble:
    seq:
      - id: magic
        -orig-id: ctp_magic
        contents: [0xf1, 0xcf]
        doc: magic number (CTF_MAGIC)
      - id: version
        -orig-id: ctp_version
        type: u1
        valid: 2
        doc: data format version number (CTF_VERSION)
        # only support version 2 for now
      - id: flags
        -orig-id: ctp_flags
        type: u1
  header:
    seq:
      - id: parent_label
        -orig-id: cth_parlabel
        type: u4
        doc: ref to name of parent lbl uniq'd against
      - id: parent_name
        -orig-id: cth_parname
        type: u4
        doc: ref to basename of parent
      - id: ofs_label_section
        -orig-id: cth_lbloff
        type: u4
        doc: offset of label section
      - id: ofs_object_section
        -orig-id: cth_objtoff
        type: u4
        doc: offset of object section
      - id: ofs_function_section
        -orig-id: cth_funcoff
        type: u4
        doc: offset of function section
      - id: ofs_type_section
        -orig-id: cth_typeoff
        type: u4
        doc: offset of type section
      - id: ofs_string_section
        -orig-id: cth_stroff
        type: u4
        doc: offset of string section
      - id: len_string_section
        -orig-id: cth_strlen
        type: u4
        doc: length of string section in bytes
