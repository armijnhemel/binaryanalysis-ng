meta:
  id: vmware_vmdk
  title: VMWare Virtual Disk
  file-extension: vmdk
  xref:
    forensicswiki: VMWare_Virtual_Disk_Format_(VMDK)
    justsolve: VMDK
    wikidata: Q2658179
  license: CC0-1.0
  endian: le
doc-ref:
 - 'https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#41-file-header'
 - https://web.archive.org/web/20210308200012/https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf
 - 'https://www.vmware.com/app/vmdk/?src=vmdk'
seq:
  - id: header
    type: header
    size: len_sector
enums:
  compression_methods:
    0: none
    1: deflate
instances:
  len_sector:
    value: 0x200
types:
  header_flags:
    doc-ref: 'https://github.com/libyal/libvmdk/blob/master/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#411-flags'
    seq:
      - id: reserved1
        type: b5
      - id: zeroed_grain_table_entry
        # 0x00000004
        type: b1
      - id: use_secondary_grain_dir
        # 0x00000002
        type: b1
      - id: valid_new_line_detection_test
        # 0x00000001
        type: b1
      - id: reserved2
        type: u1
      - id: reserved3
        type: b6
      - id: has_metadata
        # 0x00020000
        type: b1
      - id: has_compressed_grain
        # 0x00010000
        type: b1
      - id: reserved4
        type: u1
  header:
    seq:
      - id: magic
        contents: "KDMV"
      - id: version
        type: u4
        valid:
          any-of: [1, 2, 3]
      - id: flags
        type: header_flags
      - id: size_max
        type: u8
        doc: Maximum number of sectors in a given image file (capacity)
      - id: size_grain
        type: u8
        valid:
          min: 8
      - id: start_descriptor
        type: u8
        doc: Embedded descriptor file start sector number (0 if not available)
      - id: size_descriptor
        type: u8
        doc: Number of sectors that embedded descriptor file occupies
      - id: num_grain_table_entries
        type: u4
        doc: Number of grains table entries
      - id: start_secondary_grain
        type: u8
        doc: Secondary (backup) grain directory start sector number
      - id: start_primary_grain
        type: u8
        doc: Primary grain directory start sector number
      - id: size_metadata
        type: u8
      - id: is_dirty
        type: u1
      - id: error_detection
        type: error_detection
      - id: compression_method
        type: u2
        enum: compression_methods
        valid:
          any-of:
            - compression_methods::none
            - compression_methods::deflate
    types:
      error_detection:
        seq:
          - id: single_end_line_char
            contents: "\n"
          - id: non_end_line_char
            contents: " "
          - id: double_end_line_char1
            contents: "\r"
          - id: double_end_line_char2
            contents: "\n"
        doc: |
          Four entries are used to detect when an extent file has been
          corrupted by transferring it using FTP in text mode.
    instances:
      descriptor:
        pos: start_descriptor * _root.len_sector
        size: size_descriptor * _root.len_sector
        type: str
        encoding: UTF-8
        io: _root._io
        if: not start_descriptor == 0
      grain_primary:
        pos: start_primary_grain * _root.len_sector
        size: size_grain * _root.len_sector
        io: _root._io
        if: not flags.use_secondary_grain_dir and not gd_at_end
      grain_secondary:
        pos: start_secondary_grain * _root.len_sector
        size: size_grain * _root.len_sector
        io: _root._io
        if: not start_secondary_grain == 0
      gd_at_end:
        value: start_primary_grain == 0xffffffffffffffff
