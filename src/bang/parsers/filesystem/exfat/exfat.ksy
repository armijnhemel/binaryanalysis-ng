meta:
  id: exfat
  title: exfat
  license: CC0-1.0
  imports:
    - /common/bytes_with_io
  encoding: UTF-8
  endian: le
doc-ref:
  - https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
seq:
  - id: main_boot_region
    size: len_sector * 12
    type: boot_region
  - id: backup_boot_region
    size: len_sector * 12
    type: boot_region
  - id: fat_region
    size: (main_boot_region.boot_sector.ofs_fat + main_boot_region.boot_sector.len_fat * main_boot_region.boot_sector.num_fat - 24) * len_sector
    type: fat_region
  - id: data_region
    size: (main_boot_region.boot_sector.len_volume - (main_boot_region.boot_sector.ofs_fat + main_boot_region.boot_sector.len_fat * main_boot_region.boot_sector.num_fat)) * len_sector
    type: data_region
instances:
  bytes_per_sector_shift:
    pos: 108
    type: u1
    valid:
      min: 9
      max: 12
  len_sector:
    value: 1 << bytes_per_sector_shift
  sectors_per_cluster_shift:
    pos: 109
    type: u1
    valid:
      min: 0
      max: 25 - bytes_per_sector_shift
  sectors_per_cluster:
    value: 1 << sectors_per_cluster_shift
  root_directory:
    pos: 0
    io: data_region.heap.cluster[main_boot_region.boot_sector.first_cluster_of_root_directory-2]._io
    size: 32
    type: directory
types:
  boot_region:
    seq:
      - id: boot_sector
        size: _root.len_sector
        type: boot_sector
      - id: extended_boot_sectors
        size: _root.len_sector
        repeat: expr
        repeat-expr: 8
      - id: oem_parameters
        size: _root.len_sector
      - id: reserved
        size: _root.len_sector
      - id: boot_checksum
        size: _root.len_sector
  boot_sector:
    seq:
      - id: jump_boot
        contents: [0xeb, 0x76, 0x90]
      - id: file_system_name
        contents: "EXFAT   "
      - id: must_be_zero
        size: 53
      - id: ofs_partition
        type: u8
      - id: len_volume
        type: u8
      - id: ofs_fat
        type: u4
        valid:
          min: 24
      - id: len_fat
        type: u4
      - id: ofs_cluster_heap
        type: u4
      - id: num_clusters
        type: u4
      - id: first_cluster_of_root_directory
        type: u4
        valid:
          min: 2
          max: num_clusters + 1
      - id: volume_serial_number
        type: u4
      - id: revision
        type: revision
      - id: volume_flags
        type: u2
      - id: bytes_per_sector_shift
        type: u1
        valid: _root.bytes_per_sector_shift
      - id: sectors_per_cluster_shift
        type: u1
        valid:
          min: 0
          max: 25 - bytes_per_sector_shift
      - id: num_fat
        type: u1
        valid:
          any-of: [1,2]
      - id: drive_select
        type: u1
      - id: percent_in_use
        type: u1
      - id: reserved
        size: 7
      - id: boot_code
        size: 390
      - id: boot_signature
        contents: [0x55, 0xaa]
      - id: excess
        size-eos: true
    types:
      revision:
        seq:
          - id: minor
            type: u1
            valid:
              min: 0
              max: 99
          - id: major
            type: u1
            valid:
              min: 1
              max: 99
  fat_region:
    seq:
      - id: alignment
        size: (_root.main_boot_region.boot_sector.ofs_fat - 24) * _root.len_sector
      - id: first_fat
        size: (_root.main_boot_region.boot_sector.len_fat) * _root.len_sector
        type: fat
      - id: second_fat
        size: (_root.main_boot_region.boot_sector.len_fat) * (_root.main_boot_region.boot_sector.num_fat - 1) * _root.len_sector
        type: fat
        if: _root.main_boot_region.boot_sector.num_fat > 1
  fat:
    seq:
      - id: entry_0
        contents: [0xf8, 0xff, 0xff, 0xff]
      - id: entry_1
        contents: [0xff, 0xff, 0xff, 0xff]
      - id: entries
        size: 4
        repeat: expr
        repeat-expr: _root.main_boot_region.boot_sector.num_clusters
      - id: excess_space
        size-eos: true
  data_region:
    seq:
      - id: heap_alignment
        size: (_root.main_boot_region.boot_sector.ofs_cluster_heap - (_root.main_boot_region.boot_sector.ofs_fat + _root.main_boot_region.boot_sector.len_fat * _root.main_boot_region.boot_sector.num_fat)) * _root.len_sector
      - id: heap
        size: _root.main_boot_region.boot_sector.num_clusters * _root.sectors_per_cluster * _root.len_sector
        type: clusters
      - id: excess_space
        size-eos: true
    types:
      clusters:
        seq:
          - id: cluster
            size: _root.sectors_per_cluster * _root.len_sector
            type: bytes_with_io
            repeat: eos
  directory:
    seq:
      - id: first_entry
        type: entry
    types:
      entry:
        seq:
          - id: entry_type
            type: u1
          - id: data
            type:
              switch-on: importance
              cases:
                type_importance::critical: critical(category, type_code)
                type_importance::benign: benign(category, type_code)
        instances:
          in_use:
            value: entry_type & 0x80 != 0
          category:
            value: (entry_type & 0x40 != 0).to_i
            enum: type_category
          importance:
            value: (entry_type & 0x20 != 0).to_i
            enum: type_importance
          type_code:
            value: entry_type & 0b11111
            #enum: code
        enums:
          type_importance:
            0: critical
            1: benign
          type_category:
            0: primary
            1: secondary
        types:
          critical:
            params:
              - id: category
                type: u1
                enum: type_category
              - id: code
                type: u4
            seq:
              - id: entry
                type:
                  switch-on: category
                  cases:
                    type_category::primary: primary(code)
                    type_category::secondary: secondary(code)
            types:
              primary:
                params:
                  - id: code
                    type: u4
                seq:
                  - id: data
                    type:
                      switch-on: type_code
                      cases:
                        code::allocation_bitmap: allocation_bitmap
                        code::up_case_table: up_case_table
                        code::volume_label: volume_label
                        code::file_directory: file_directory
                        _: generic
                instances:
                  type_code:
                    value: code
                    enum: code
                enums:
                  code:
                    1: allocation_bitmap
                    2: up_case_table
                    3: volume_label
                    5: file_directory
              secondary:
                params:
                  - id: code
                    type: u4
                seq:
                  - id: data
                    type:
                      switch-on: type_code
                      cases:
                        code::stream_extension: stream_extension
                        code::file_name_directory: file_name_directory
                        _: generic
                instances:
                  type_code:
                    value: code
                    enum: code
                enums:
                  code:
                    0: stream_extension
                    1: file_name_directory
          benign:
            params:
              - id: category
                type: u1
                enum: type_category
              - id: code
                type: u4
            seq:
              - id: entry
                type:
                  switch-on: category
                  cases:
                    type_category::primary: primary(code)
                    type_category::secondary: secondary(code)
            types:
              primary:
                params:
                  - id: code
                    type: u4
                seq:
                  - id: data
                    type:
                      switch-on: type_code
                      cases:
                        code::volume_guid: volume_guid
                        #code::texfat_padding: texfat_padding
                        _: generic
                instances:
                  type_code:
                    value: code
                    enum: code
                enums:
                  code:
                    0: volume_guid
                    1: texfat_padding
              secondary:
                params:
                  - id: code
                    type: u4
                seq:
                  - id: data
                    type:
                      switch-on: type_code
                      cases:
                        code::vendor_extension: vendor_extension
                        code::vendor_allocation: vendor_allocation
                        _: generic
                instances:
                  type_code:
                    value: code
                    enum: code
                enums:
                  code:
                    0: vendor_extension
                    1: vendor_allocation
          allocation_bitmap:
            seq:
              - id: bitmap_flags
                type: u1
              - id: reserved
                size: 18
              - id: first_cluster
                type: u4
              - id: len_data
                type: u8
          up_case_table:
            seq:
              - id: reserved_1
                size: 3
              - id: table_checksum
                type: u4
              - id: reserved_2
                size: 12
              - id: first_cluster
                type: u4
              - id: len_data
                type: u8
          volume_label:
            seq:
              - id: num_characters
                type: u1
              - id: label
                size: 22
                #size: num_characters
                #type: strz
                #encoding: utf16le
              - id: reserved
                size: 8
          file_directory:
            seq:
              - id: secondary_count
                type: u1
              - id: set_checksum
                type: u2
              - id: file_attributes
                type: u2
              - id: reserved_1
                size: 2
              - id: ctime
                type: u4
              - id: mtime
                type: u4
              - id: atime
                type: u4
              - id: ctime_ms_increment
                type: u1
              - id: mtime_ms_increment
                type: u1
              - id: ctime_utc_offset
                type: u1
              - id: mtime_utc_offset
                type: u1
              - id: atime_utc_offset
                type: u1
              - id: reserved_2
                size: 7
          stream_extension:
            seq:
              - id: general_secondary_flags
                type: u1
              - id: reserved_1
                size: 1
              - id: len_name
                type: u1
              - id: name_hash
                type: u2
              - id: reserved_2
                size: 2
              - id: valid_data_length
                type: u8
              - id: reserved_3
                size: 4
              - id: first_cluster
                type: u4
              - id: len_data
                type: u8
          file_name_directory:
            seq:
              - id: general_secondary_flags
                type: u1
              - id: file_name
                size-eos: true
          vendor_allocation:
            seq:
              - id: general_secondary_flags
                type: u1
              - id: vendor_guid
                size: 16
              - id: vendor_defined
                type: u2
              - id: first_cluster
                type: u4
              - id: len_data
                type: u8
          vendor_extension:
            seq:
              - id: general_secondary_flags
                type: u1
              - id: vendor_guid
                size: 16
              - id: vendor_defined
                size: 14
          volume_guid:
            seq:
              - id: secondary_count
                type: u1
              - id: set_checksum
                type: u2
              - id: general_primary_flags
                type: u2
              - id: volume_guid
                size: 16
              - id: reserved
                size: 10
          generic:
            seq:
              - id: custom
                size: 19
              - id: first_cluster
                type: u4
              - id: len_data
                type: u8
enums:
  type_importance:
    0: critical
    1: benign
