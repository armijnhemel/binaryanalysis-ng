meta:
  id: iso9660
  title: ISO9660 CD filesystem
  file-extension: iso
  xref:
    loc: fdd000348
    pronom: fmt/468
    wikidata: Q815645
  license: CC0-1.0
  ks-version: 0.9
  bit-endian: be
  endian: be
  encoding: ASCII
doc: |
  ISO9660 is standard filesystem used on read-only optical discs
  (mostly CD-ROM). The standard was based on earlier High Sierra
  Format (HSF), proposed for CD-ROMs in 1985, and, after several
  revisions, it was accepted as ISO9660:1998.
  The format emphasizes portability (thus having pretty minimal
  features and very conservative file names standards) and sequential
  access (which favors disc devices with relatively slow rotation
  speed).

  SUSP: IEEE P1281
  RockRidge: IEEE P1282
doc-ref:
  - ecma-119 https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf
  - susp https://web.archive.org/web/20170404132301/http://www.ymi.com/ymi/sites/default/files/pdf/Systems%20Use%20P1281.pdf
  - rrip https://web.archive.org/web/20170404043745/http://www.ymi.com/ymi/sites/default/files/pdf/Rockridge.pdf
  - rras http://www.estamos.de/makecd/Rock_Ridge_Amiga_Specific
  - rrzf https://web.archive.org/web/20200612093441/https://dev.lovelyhq.com/libburnia/web/-/wikis/zisofs
  - aaip http://fileformats.archiveteam.org/wiki/AAIP
  - apple extensions http://fileformats.archiveteam.org/wiki/Apple_ISO_9660_extensions
seq:
  - id: system_area
    size: 16 * sector_size
    doc-ref: ecma-119 6.2.1
  - id: data_area
    type: volume_descriptor
    size: sector_size
    repeat: until
    repeat-until: _.type == volume_type::set_terminator
instances:
  sector_size:
    doc-ref: ecma-119 6.1.2
    value: 0x800
enums:
  volume_type:
    0x00: boot_record
    0x01: primary
    0x02: supplementary
    0x03: volume_partition
    0xff: set_terminator
types:
  u2bi:
    doc-ref: ecma-119 7.2.3
    seq:
      - id: le
        type: u2le
      - id: be
        type: u2be
        valid: le
    instances:
      value:
        value: le
  u4bi:
    doc-ref: ecma-119 7.3.3
    seq:
      - id: le
        type: u4le
      - id: be
        type: u4be
        valid: le
    instances:
      value:
        value: le
  datetime_long:
    doc-ref: ecma-119 8.4.26.1
    seq:
      - id: year_string
        type: str
        size: 4
      - id: month_string
        type: str
        size: 2
      - id: day_string
        type: str
        size: 2
      - id: hour_string
        type: str
        size: 2
      - id: minute_string
        type: str
        size: 2
      - id: second_string
        type: str
        size: 2
      - id: hundredths_second_string
        type: str
        size: 2
      - id: timezone_offset
        type: s1
    instances:
      year:
        value: year_string.to_i
      month:
        value: month_string.to_i
      day:
        value: day_string.to_i
      hour:
        value: hour_string.to_i
      minute:
        value: minute_string.to_i
      second:
        value: second_string.to_i
      hundredths_second:
        value: hundredths_second_string.to_i
      valid_date:
        value: month <= 12 and day <= 31 and hour <= 23 and minute <= 59 and second <= 59
  datetime_short:
    doc-ref: ecma-119 9.1.5
    seq:
      - id: year
        type: u1
      - id: month
        type: u1
      - id: day
        type: u1
      - id: hour
        type: u1
      - id: min
        type: u1
      - id: sec
        type: u1
      - id: offset
        type: s1
  volume_descriptor:
    doc-ref: ecma-119 8.1
    seq:
      - id: type
        -orig-id: volume_descriptor_type
        doc-ref: ecma-119 8.1.1
        type: u1
        enum: volume_type
      - id: magic
        doc-ref: ecma-119 8.1.2
        contents: CD001
      - id: version
        doc-ref: ecma-119 8.1.3
        type: u1
        valid:
          any-of: [1, 2]
      - id: volume
        type:
          switch-on: type
          cases:
            'volume_type::boot_record': boot_record
            'volume_type::primary': primary
            'volume_type::supplementary': supplementary
            #'volume_type::volume_partition': partition
    types:
      text32:
        seq:
          - id: text
            type: str
            size: 32
      text37:
        seq:
          - id: text
            type: str
            size: 37
      text128:
        seq:
          - id: text
            type: str
            size: 128
      boot_record:
        doc-ref: ecma-119 8.2
        seq:
          - id: boot_system_identifier
            doc-ref: ecma-119 8.2.4
            type: strz
            size: 32
          - id: boot_identifier
            doc-ref: ecma-119 8.2.5
            type: strz
            size: 32
      primary:
        doc-ref: ecma-119 8.4
        seq:
          - id: unused01
            doc-ref: ecma-119 8.4.4
            contents: [ 0x0 ]
          - id: system_identifier
            doc-ref: ecma-119 8.4.5
            type: text32
          - id: volume_identifier
            doc-ref: ecma-119 8.4.6
            type: text32
          - id: unused02
            doc-ref: ecma-119 8.4.7
            contents: [ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ]
          - id: volume_space_size
            doc-ref: ecma-119 8.4.8
            type: u4bi
          - id: unused03
            doc-ref: ecma-119 8.4.9
            contents: [
              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ]
          - id: volume_set_size
            doc-ref: ecma-119 8.4.10
            type: u2bi
          - id: volume_sequence_number
            doc-ref: ecma-119 8.4.11
            type: u2bi
          - id: logical_block_size
            doc-ref: ecma-119 8.4.12
            type: u2bi
          - id: path_table_size
            doc-ref: ecma-119 8.4.13
            type: u4bi
          - id: loc_l_path_table
            doc-ref: ecma-119 8.4.14
            type: u4le
          - id: loc_opt_l_path_table
            doc-ref: ecma-119 8.4.15
            type: u4le
          - id: loc_m_path_table
            doc-ref: ecma-119 8.4.16
            type: u4be
          - id: loc_opt_m_path_table
            doc-ref: ecma-119 8.4.17
            type: u4be
          - id: root_directory
            doc-ref: ecma-119 8.4.18
            doc: |
              The root directory_record with body is 34 bytes.
              In other cases the size is variable.
            type: directory_record
            size: 34
          - id: volume_set_identifier
            doc-ref: ecma-119 8.4.19
            type: text128
          - id: publisher_identifier
            doc-ref: ecma-119 8.4.20
            type: text128
          - id: data_preparer_identifier
            doc-ref: ecma-119 8.4.21
            type: text128
          - id: application_identifier
            doc-ref: ecma-119 8.4.22
            type: text128
          - id: copyright_file_identifier
            doc-ref: ecma-119 8.4.23
            type: text37
          - id: abstract_file_identifier
            doc-ref: ecma-119 8.4.24
            type: text37
          - id: bibliographic_file_identifier
            doc-ref: ecma-119 8.4.25
            type: text37
          - id: volume_creation_date_and_time
            doc-ref: ecma-119 8.4.26
            type: datetime_long
          - id: volume_modification_date_and_time
            doc-ref: ecma-119 8.4.27
            type: datetime_long
          - id: volume_expiration_date_and_time
            doc-ref: ecma-119 8.4.28
            type: datetime_long
          - id: volume_effective_date_and_time
            doc-ref: ecma-119 8.4.29
            type: datetime_long
          - id: file_structure_version
            doc-ref: ecma-119 8.4.31
            type: s1
        instances:
          path_table:
            io: _root._io
            pos: _root.sector_size * loc_l_path_table
            size: path_table_size.value
            type: path_table_records
      supplementary:
        doc-ref: ecma-119 8.5
        seq:
          - id: volume_flags_reserved
            doc-ref: ecma-119 8.5.3 b1-b7
            type: b7
          - id: volume_flags_not_iso2375
            doc-ref: ecma-119 8.5.3 b0
            type: b1
          - id: system_identifier
            doc-ref: ecma-119 8.5.4
            type: text32
          - id: volume_identifier
            doc-ref: ecma-119 8.5.5
            type: text32
          - id: unused01
            doc-ref: ecma-119 8.5
            contents: [ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ]
          - id: volume_space_size
            doc-ref: ecma-119 8.5
            type: u4bi
          - id: escape_sequences
            doc-ref: ecma-119 8.5.6
            doc: |
              This will not be all 0x0.
              This field can trigger the Directory Records to switch from ASCII to ISO-2022 ( UTF-8 in this code )
            size: 32
          - id: volume_set_size
            doc-ref: ecma-119 8.5
            type: u2bi
          - id: volume_sequence_number
            doc-ref: ecma-119 8.5
            type: u2bi
          - id: logical_block_size
            doc-ref: ecma-119 8.5
            type: u2bi
          - id: path_table_size
            doc-ref: ecma-119 8.5.7
            type: u4bi
          - id: loc_l_path_table
            doc-ref: ecma-119 8.5.8
            type: u4le
          - id: loc_opt_l_path_table
            doc-ref: ecma-119 8.5.9
            type: u4le
          - id: loc_m_path_table
            doc-ref: ecma-119 8.5.10
            type: u4be
          - id: loc_opt_m_path_table
            doc-ref: ecma-119 8.5.11
            type: u4be
          - id: root_directory
            doc-ref: ecma-119 8.5.12
            doc: |
              The root directory_record with body is 34 bytes.
              In other cases the size is variable.
            type: directory_record
            size: 34
          - id: volume_set_identifier
            doc-ref: ecma-119 8.5.13
            type: text128
          - id: publisher_identifier
            doc-ref: ecma-119 8.5.14
            type: text128
          - id: data_preparer_identifier
            doc-ref: ecma-119 8.5.15
            type: text128
          - id: application_identifier
            doc-ref: ecma-119 8.5.16
            type: text128
          - id: copyright_file_identifier
            doc-ref: ecma-119 8.5.17
            type: text37
          - id: abstract_file_identifier
            doc-ref: ecma-119 8.5.18
            type: text37
          - id: bibliographic_file_identifier
            doc-ref: ecma-119 8.5.19
            type: text37
          - id: volume_creation_date_and_time
            doc-ref: ecma-119 8.5
            type: datetime_long
          - id: volume_modification_date_and_time
            doc-ref: ecma-119 8.5
            type: datetime_long
          - id: volume_expiration_date_and_time
            doc-ref: ecma-119 8.5
            type: datetime_long
          - id: volume_effective_date_and_time
            doc-ref: ecma-119 8.5
            type: datetime_long
          - id: file_structure_version
            doc-ref: ecma-119 8.5
            type: s1
        instances:
          path_table:
            io: _root._io
            pos: _root.sector_size * loc_l_path_table
            size: path_table_size.value
            type: path_table_records
      path_table_records:
        doc-ref: ecma-119 9.4
        seq:
          - id: path_table_record
            type: path_table_record
            repeat: eos
        types:
          path_table_record:
            doc-ref: ecma-119 9.4
            seq:
              - id: len_dir_name
                doc-ref: ecma-119 9.4.1
                type: u1
              - id: len_ext_rec
                doc-ref: ecma-119 9.4.2
                type: u1
              - id: loc_ext
                doc-ref: ecma-119 9.4.3
                type: u4le
              - id: parent_dir_num
                doc-ref: ecma-119 9.4.4
                type: u2le
              - id: dir_name
                doc-ref: ecma-119 9.4.5
                type: str
                size: len_dir_name
              - id: padding_field
                doc-ref: ecma-119 9.4.6
                doc: |
                  Padding field is added when len_dir_name contains an odd number
                contents: [ 0x0 ]
                if: len_dir_name % 2 == 1
            instances:
              directory_records:
                io: _root._io
                pos: _root.sector_size * loc_ext
                size: _root.sector_size
                type: directory_record
      directory_records:
        doc: |
          First item "." points to it self
          Second item ".." points to the parent, or also to self if it is the root
        seq:
          - id: records
            type: directory_record
            repeat: until
            repeat-until: _io.eof or (_io.size - _io.pos < 34)
      directory_record:
        doc-ref: ecma-119 9.1
        seq:
          - id: len_dr
            doc-ref: ecma-119 9.1.1
            doc: |
              If len_dr == 0 we do not process the body
              If len_dr >= 1 we include field len_dr in the size
            type: u1
          - id: body
            type: body
            size: len_dr - len_dr._sizeof
            if: len_dr > 0x0
        types:
          body:
            seq:
              - id: ext_attr_rec_len
                doc-ref: ecma-119 9.1.2
                type: u1
              - id: extent
                doc-ref: ecma-119 9.1.3
                type: u4bi
              - id: data_len
                doc-ref: ecma-119 9.1.4
                type: u4bi
              - id: rec_date_time
                doc-ref: ecma-119 9.1.5
                type: datetime_short
              - id: file_flags_multi_extent
                doc-ref: ecma-119 9.1.6 b7
                type: b1
              - id: file_flags_reserved
                doc-ref: ecma-119 9.1.6 b5+b6
                type: b2
              - id: file_flags_protection
                doc-ref: ecma-119 9.1.6 b4
                type: b1
              - id: file_flags_record
                doc-ref: ecma-119 9.1.6 b3
                type: b1
              - id: file_flags_associated_file
                doc-ref: ecma-119 9.1.6 b2
                type: b1
              - id: file_flags_directory
                doc-ref: ecma-119 9.1.6 b1
                type: b1
              - id: file_flags_existence
                doc-ref: ecma-119 9.1.6 b0
                type: b1
              - id: file_unit_size
                doc-ref: ecma-119 9.1.7
                type: u1
              - id: interleave_gap_size
                doc-ref: ecma-119 9.1.8
                type: u1
              - id: vol_seq_num
                doc-ref: ecma-119 9.1.9
                type: u2bi
              - id: len_fi
                doc-ref: ecma-119 9.1.10
                type: u1
              - id: file_id
                doc-ref: ecma-119 9.1.11
                type: str
                size: len_fi
              - id: padding_field
                doc-ref: ecma-119 9.1.12
                doc: |
                  Padding field is added when len_fi contains an even number
                contents: [ 0x0 ]
                if: len_fi % 2 == 0
              - id: system_use
                doc-ref: ecma-119 9.1.13
                type: susp
                size-eos: true
            instances:
              directory_records:
                io: _root._io
                pos: _root.sector_size * extent.value
                size: data_len.value
                type: directory_records
                if: ( _parent.len_dr > 0x0 ) and file_flags_directory
              file_content:
                io: _root._io
                pos: _root.sector_size * extent.value
                size: data_len.value
                if: ( _parent.len_dr > 0x0 ) and not file_flags_directory
            types:
              susp:
                doc: |
                  We check if we have at least 4 bytes left.
                  The SUSP magic is 2 bytes. A complete SUSP entry
                  is at least 4 bytes long.
                seq:
                  - id: entries
                    type: header
                    if: _io.size - _io.pos >= 4
                    repeat: until
                    repeat-until: _io.size - _io.pos < 4
                types:
                  header:
                    seq:
                      - id: signature
                        type: u2be
                        enum: signature
                      - id: length
                        type: u1
                      - id: version
                        type: u1
                        #valid: 1
                      - id: susp_data
                        size: length - (signature._sizeof + length._sizeof + version._sizeof) # note: this `_sizeof` sum should probably be in a `value` instance
                        type:
                          switch-on: signature
                          cases:
                            'signature::apple_attribute_list': susp_unknown # AA
                            'signature::aaip_attribute_list': susp_unknown # AL
                            'signature::rras_amiga_specific': rras_as # AS
                            'signature::susp_continuation_area': susp_ce # CE
                            'signature::rrip_child_link': rrip_cl # CL
                            'signature::susp_extensions_reference': susp_er # ER
                            'signature::susp_extension_selector': susp_es # ES
                            'signature::rrip_alternate_name': rrip_nm # NM
                            'signature::susp_padding_field': susp_pd # PD
                            'signature::rrip_parent_link': rrip_pl # PL
                            'signature::rrip_posix_device_number': rrip_pn # PN
                            'signature::rrip_posix_file_attributes': rrip_px # PX
                            'signature::rrip_relocated_directory': rrip_re # RE
                            'signature::rrip_extensions_in_use_indicator': susp_unknown # RR
                            'signature::rrip_sparse_file': rrip_sf # SF
                            'signature::rrip_symbolic_link': susp_sl # SL
                            'signature::susp_indicator': susp_sp # SP
                            'signature::susp_terminator': susp_st # ST
                            'signature::rrip_time_file': rrip_tf # TF
                            'signature::rrzf_zisofs': rrzf_zf # ZF
                    enums:
                      signature:
                        0x4141: apple_attribute_list # AA
                        0x414c: aaip_attribute_list # AL
                        0x4153: rras_amiga_specific # AS
                        0x4345: susp_continuation_area # CE
                        0x434c: rrip_child_link # CL
                        0x4552: susp_extensions_reference # ER
                        0x4553: susp_extension_selector # ES
                        0x4e4d: rrip_alternate_name # NM
                        0x5044: susp_padding_field # PD
                        0x504c: rrip_parent_link # PL
                        0x504e: rrip_posix_device_number # PN
                        0x5058: rrip_posix_file_attributes # PX
                        0x5245: rrip_relocated_directory # RE
                        0x5252: rrip_extensions_in_use_indicator # RR
                        0x5346: rrip_sparse_file # SF
                        0x534c: rrip_symbolic_link # SL
                        0x5350: susp_indicator # SP
                        0x5354: susp_terminator # ST
                        0x5446: rrip_time_file # TF
                        0x5a46: rrzf_zisofs # ZF
                    types:
                      rras_as:
                        doc-ref: rras
                        seq:
                          - id: reserved
                            type: b5
                          - id: flag_continue
                            type: b1
                          - id: flag_comment
                            type: b1
                          - id: flag_protection
                            type: b1
                          - id: flags
                            doc-ref: rras 6
                            type: flags
                            if: flag_protection
                          - id: len_comment
                            doc-ref: rras 7a
                            type: u1
                            if: flag_comment or flag_continue
                          - id: comment
                            doc-ref: rras 7b
                            type: str
                            size-eos: true
                            if: flag_comment or flag_continue
                        types:
                          flags:
                            doc-ref: rras 6
                            seq:
                              - id: user_bitfields
                                doc-ref: rras 6a
                                type: u1
                              - id: reserved_bitfields
                                doc-ref: rras 6b
                                type: u1
                              - id: other_read
                                doc-ref: rras 6c.7
                                type: b1
                              - id: other_write
                                doc-ref: rras 6c.6
                                type: b1
                              - id: other_exec
                                doc-ref: rras 6c.5
                                type: b1
                              - id: other_del
                                doc-ref: rras 6c.4
                                type: b1
                              - id: group_read
                                doc-ref: rras 6c.3
                                type: b1
                              - id: group_write
                                doc-ref: rras 6c.2
                                type: b1
                              - id: group_exec
                                doc-ref: rras 6c.1
                                type: b1
                              - id: group_del
                                doc-ref: rras 6c.0
                                type: b1
                              - id: reserved
                                doc-ref: rras 6d.7
                                type: b1
                              - id: exec_script
                                doc-ref: rras 6d.6
                                type: b1
                              - id: reent_exec
                                doc-ref: rras 6d.5
                                type: b1
                              - id: archived
                                doc-ref: rras 6d.4
                                type: b1
                              - id: owner_read
                                doc-ref: rras 6d.3
                                type: b1
                              - id: owner_write
                                doc-ref: rras 6d.2
                                type: b1
                              - id: owner_exec
                                doc-ref: rras 6d.1
                                type: b1
                              - id: owner_del
                                doc-ref: rras 6d.0
                                type: b1
                      susp_ce:
                        doc-ref: susp 5.1
                        seq:
                          - id: ca_location
                            type: u4bi
                          - id: ca_offset
                            type: u4bi
                          - id: ca_length
                            type: u4bi
                      rrip_cl:
                        doc-ref: rrip 4.1.5.1
                        seq:
                          - id: lba_child
                            type: u4bi
                      susp_er:
                        doc-ref: susp 5.5
                        seq:
                          - id: len_id
                            type: u1
                          - id: len_des
                            type: u1
                          - id: len_src
                            type: u1
                          - id: ext_ver
                            type: u1
                          - id: ext_id
                            size: len_id
                          - id: ext_des
                            size: len_des
                          - id: ext_src
                            size: len_src
                      susp_es:
                        doc-ref: susp 5.6
                        seq:
                          - id: ext_seq
                            type: u1
                      rrip_nm:
                        doc-ref: rrip 4.1.4
                        seq:
                          - id: reserved
                            doc: |
                              Grouped all 4x reserved into a single reserved
                            type: b5
                          - id: parent
                            type: b1
                          - id: current
                            type: b1
                          - id: continued
                            type: b1
                          - id: name
                            type: str
                            size-eos: true
                      susp_pd:
                        doc-ref: susp 5.2
                        seq:
                          - id: padding_area
                            size-eos: true
                      rrip_pl:
                        doc-ref: rrip 4.1.5.2
                        seq:
                          - id: lba_parent
                            type: u4bi
                      rrip_pn:
                        doc-ref: rrip 4.1.2
                        seq:
                          - id: dev_t_high
                            type: u4bi
                          - id: dev_t_low
                            type: u4bi
                      rrip_px:
                        doc-ref: rrip 4.1.1
                        seq:
                          - id: file_mode
                            type: u4bi
                          - id: links
                            type: u4bi
                          - id: user
                            type: u4bi
                          - id: group
                            type: u4bi
                          - id: serial
                            type: u4bi
                            if: _parent.length >= 44
                      #doc-ref: rrip 4.1.5.3
                      rrip_re: {}
                      rrip_sf:
                        doc-ref: rrip 4.1.7
                        seq:
                          - id: virtual_file_size_high
                            type: u4bi
                          - id: virtual_file_size_low
                            type: u4bi
                          - id: table_depth
                            type: u1
                            enum: table_depth
                        enums:
                          table_depth:
                            0x2: max_64kb
                            0x4: max_64mb
                            0x8: max_4gb
                            0x10: max_1tb
                            0x20: max_256tb
                            0x40: max_64pb
                            0x80: max_16eb
                      susp_sl:
                        doc-ref: susp 4.1.3.1
                        seq:
                          - id: reserved
                            type: b7
                          - id: continued
                            type: b1
                          - id: component_records
                            type: susp_sl_component_record
                            repeat: eos
                      susp_sl_component_record:
                        doc-ref: susp 4.1.3.1
                        seq:
                          - id: reserved
                            type: b4
                          - id: root
                            type: b1
                          - id: parent
                            type: b1
                          - id: current
                            type: b1
                          - id: continued
                            type: b1
                          - id: len_component
                            type: u1
                          - id: content
                            type: str
                            size: len_component
                      susp_sp:
                        doc-ref: susp 5.3
                        seq:
                          - id: check_bytes
                            contents: [ 0xbe, 0xef ]
                          - id: len_skp
                            size-eos: true
                      # doc-ref: susp 5.4
                      susp_st: {}
                      rrip_tf:
                        doc-ref: rrip 4.6.1
                        seq:
                          - id: long_form
                            type: b1
                          - id: effective
                            type: b1
                          - id: expiration
                            type: b1
                          - id: backup
                            type: b1
                          - id: attributes
                            type: b1
                          - id: access
                            type: b1
                          - id: modify
                            type: b1
                          - id: creation
                            type: b1
                          - id: datetime_short
                            type: short
                            if: not long_form
                          - id: datetime_long
                            type: long
                            if: long_form
                        types:
                          short:
                            doc-ref: rrip 4.6.1
                            doc: |
                              The data is available in this specific order.
                              Multiple dates can be set.
                            seq:
                              - id: creation
                                type: datetime_short
                                if: _parent.creation
                              - id: modify
                                type: datetime_short
                                if: _parent.modify
                              - id: access
                                type: datetime_short
                                if: _parent.access
                              - id: attributes
                                type: datetime_short
                                if: _parent.attributes
                              - id: backup
                                type: datetime_short
                                if: _parent.backup
                              - id: expiration
                                type: datetime_short
                                if: _parent.expiration
                              - id: effective
                                type: datetime_short
                                if: _parent.effective
                          long:
                            doc-ref: rrip 4.6.1
                            doc: |
                              The data is available in this specific order.
                              Multiple dates can be set.
                            seq:
                              - id: creation
                                type: datetime_long
                                if: _parent.creation
                              - id: modify
                                type: datetime_long
                                if: _parent.modify
                              - id: access
                                type: datetime_long
                                if: _parent.access
                              - id: attributes
                                type: datetime_long
                                if: _parent.attributes
                              - id: backup
                                type: datetime_long
                                if: _parent.backup
                              - id: expiration
                                type: datetime_long
                                if: _parent.expiration
                              - id: effective
                                type: datetime_long
                                if: _parent.effective
                      rrzf_zf:
                        doc-ref: rrzf
                        seq:
                          - id: algorithm
                            type: u2be
                            enum: algorithm
                          - id: header_size
                            doc: |
                              value is divided by 4
                            type: u1
                          - id: block_size
                            type: u1
                            enum: block_size
                          - id: uncompressed_size
                            type: u4bi
                        enums:
                          algorithm:
                            0x707a: paged_zlib # pz
                          block_size:
                            0xf: bs_32kib
                            0x10: bs_64kib
                            0x11: bs_128kib
                      susp_unknown: # default for now
                        seq:
                          - id: data
                            size-eos: true
