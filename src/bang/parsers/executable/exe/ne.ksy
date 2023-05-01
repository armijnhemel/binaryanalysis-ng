meta:
  id: ne
  title: New Executable
  file-extension:
    - exe
    - dll
  tags:
    - dos
  license: CC0-1.0
  ks-version: 0.9
  encoding: ASCII
  endian: le
doc-ref: http://benoit.papillault.free.fr/c/disc2/exefmt.txt
seq:
  - id: header
    type: exe_header
  - id: body
    size: header.len_body
instances:
  relocations:
    pos: header.mz.ofs_relocations
    io: header._io
    type: relocation
    repeat: expr
    repeat-expr: header.mz.num_relocations
    if: header.mz.ofs_relocations != 0
types:
  exe_header:
    seq:
      - id: mz
        type: mz_header
      - id: rest_of_header
        size: mz.len_header - mz._sizeof
    instances:
      len_body:
        value: '(mz.last_page_extra_bytes == 0 ? mz.num_pages * 512 : (mz.num_pages - 1) * 512 + mz.last_page_extra_bytes) - mz.len_header'
  mz_header:
    seq:
      - id: magic
        size: 2
        type: str
        valid:
          any-of:
            - '"MZ"'
            - '"ZM"'
      - id: last_page_extra_bytes
        type: u2
        valid:
          max: 511
      - id: num_pages
        type: u2
      - id: num_relocations
        type: u2
      - id: header_size
        type: u2
      - id: min_allocation
        type: u2
      - id: max_allocation
        type: u2
      - id: initial_ss
        type: u2
      - id: initial_sp
        type: u2
      - id: checksum
        type: u2
      - id: initial_ip
        type: u2
      - id: initial_cs
        type: u2
      - id: ofs_relocations
        type: u2
      - id: overlay_id
        type: u2
        valid: 0
    instances:
      len_header:
        value: header_size * 16
  relocation:
    seq:
      - id: ofs
        type: u2
      - id: seg
        type: u2
