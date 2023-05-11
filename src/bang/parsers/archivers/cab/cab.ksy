meta:
  id: cab
  title: MS-CAB
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc-ref: https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf
seq:
  - id: preheader
    type: preheader
  - id: cab_data
    size: preheader.len_cabinet - preheader._sizeof
    type: cab_data
types:
  preheader:
    seq:
      - id: magic
        contents: 'MSCF'
      - id: reserved1
        contents: [0, 0, 0, 0]
      - id: len_cabinet
        type: u4
  cab_data:
    seq:
      - id: header
        type: header
      - id: first_folder
        type: folder
      - id: data
        size-eos: true
  header:
    seq:
      - id: reserved2
        size: 4
        contents: [0, 0, 0, 0]
      - id: ofs_cffile
        type: u4
        valid:
          max: _root.preheader.len_cabinet
      - id: reserved3
        size: 4
        contents: [0, 0, 0, 0]
      - id: version
        type: version
      - id: num_folders
        type: u2
      - id: num_files
        type: u2
      - id: flags
        type: u2
      - id: set_id
        type: u2
      - id: cabinet_number
        type: u2
      - id: len_per_cabinet_reserved
        -orig-id: cbCFHeader
        type: u2
        valid:
          min: 0
          max: 60000
        if: reserve_present
        doc: (optional) size of per-cabinet reserved area
      - id: len_per_folder_reserved
        -orig-id: cbCFFolder
        type: u1
        valid:
          min: 0
          max: 255
        if: reserve_present
        doc: (optional) size of per-folder reserved area
      - id: len_per_datablock_reserved
        -orig-id: cbCFData
        type: u1
        valid:
          min: 0
          max: 255
        if: reserve_present
        doc: (optional) size of per-datablock reserved area
      - id: per_cabinet_reserved_area
        size: len_per_cabinet_reserved
        if: reserve_present
        doc: (optional) per-cabinet reserved area
      - id: previous_cabinet
        type: strz
        encoding: ASCII
        if: has_previous_cabinet
        doc: (optional) name of previous cabinet file
      - id: previous_disk
        type: strz
        encoding: ASCII
        if: has_previous_cabinet
        doc: (optional) name of previous disk
      - id: next_cabinet
        type: strz
        encoding: ASCII
        if: has_next_cabinet
        doc: (optional) name of next cabinet file
      - id: next_disk
        type: strz
        encoding: ASCII
        if: has_next_cabinet
        doc: (optional) (optional) name of next disk
    instances:
      has_previous_cabinet:
        value: flags & 0x1 == 1
      has_next_cabinet:
        value: flags & 0x2 == 2
      reserve_present:
        value: flags & 0x4 == 4
  version:
    seq:
      - id: minor
        type: u1
      - id: major
        type: u1
  folder:
    seq:
      - id: ofs_cab_start
        -orig-id: coffCabStart
        type: u4
        doc: offset of the first CFDATA block in this folder
      - id: num_cfdata_blocks
        type: u2
        doc: number of CFDATA blocks in this folder
      - id: type_compress
        type: u2
        doc: compression type indicator
      - id: per_folder_reserved_area
        size: _parent.header.len_per_folder_reserved
        if: _parent.header.reserve_present
        doc: (optional) per-folder reserved area
