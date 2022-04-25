meta:
  id: pcp
  title: Performance Co-Pilot
  tags:
    - linux
    - log
  license: CC0-1.0
  encoding: UTF-8
  endian: be
doc-ref:
  - https://github.com/performancecopilot/pcp/blob/main/man/man5/LOGARCHIVE.5
  - https://man7.org/linux/man-pages/man5/LOGARCHIVE.5.html
seq:
  - id: len_record1
    type: u4
    valid: 132
  - id: header
    type: header
    size: len_record1 - len_record1._sizeof * 2
  - id: len_record2
    type: u4
    valid: len_record1
  - id: records
    type:
      switch-on: header.log_volume_number
      cases:
        -1: meta
        -2: index
        #_: archive
    repeat: eos
types:
  header:
    seq:
      - id: magic
        contents: [0x50, 0x05, 0x26]
      - id: version
        type: u1
        valid: 2
      - id: logger_pid
        -orig-id: ll_pid
        type: u4
      - id: seconds
        type: u4
        doc: log start time, seconds part (past UNIX epoch)
      - id: microseconds
        type: u4
        doc: log start time, microseconds part
      - id: log_volume_number
        type: s4
        valid:
          #any-of: [-1, -2]
          any-of: [-1]
        doc: current log volume number (or -1=.meta, -2=.index)
      - id: hostname
        size: 64
        type: strz
      - id: timezone
        size: 40
        type: strz
  meta:
    -webide-representation: '{meta_record.tag}'
    seq:
      - id: len_record1
        type: u4
      - id: meta_record
        type: meta_record
        size: len_record1 - len_record1._sizeof * 2
      - id: len_record2
        type: u4
        valid: len_record1
  meta_record:
    -webide-representation: '{tag}'
    seq:
      - id: tag
        type: u4
        enum: meta_records
        valid:
          any-of:
            - meta_records::description
            - meta_records::instance_domain
            - meta_records::label
            - meta_records::text
      - id: record
        type:
          switch-on: tag
          cases:
            meta_records::description: description
            meta_records::instance_domain: instance_domain
            meta_records::label: label
            meta_records::text: text
  description:
    seq:
      - id: pmid
        type: u4
      - id: pm_type
        type: u4
      - id: instance_domain
        type: u4
      - id: semantics
        type: u4
      - id: units
        type: u4
      - id: num_alternatives
        type: u4
      - id: names
        type: meta_name
        repeat: expr
        repeat-expr: num_alternatives
  meta_name:
    seq:
      - id: len_name
        type: u4
      - id: name
        type: str
        size: len_name
  instance_domain:
    seq:
      - id: seconds
        type: u4
        doc: timestamp, seconds part (past UNIX epoch)
      - id: microseconds
        type: u4
        doc: timestamp, microseconds part
      - id: instance_domain
        type: u4
      - id: num_instances
        type: u4
      - id: instance_numbers
        type: u4
        repeat: expr
        repeat-expr: num_instances
      - id: offsets
        type: u4
        repeat: expr
        repeat-expr: num_instances
      - id: names
        type: strz
        repeat: expr
        repeat-expr: num_instances
  label:
    seq:
      - id: seconds
        type: u4
        doc: timestamp, seconds part (past UNIX epoch)
      - id: microseconds
        type: u4
        doc: timestamp, microseconds part
      - id: label_type
        type: u4
        enum: label_types
        valid:
          any-of:
            - label_types::context
            - label_types::domain
            - label_types::indom
            - label_types::cluster
            - label_types::item
            - label_types::instances
      - id: numeric_identifier
        type: s4
      - id: num_instances
        type: u4
      - id: ofs_jsonb
        type: u4
        doc: not always present?
      #- id: labelset_entries
      #  type: labelset_entry
      #  repeat: expr
      #- id: jsonb
      #  size-eos: true
  labelset_entry:
    seq:
      - id: instance_identifier
        type: s4
      - id: len_jsonb
        type: u4
      - id: num_labels
        type: u4
      - id: labels
        type: label_entry
        repeat: expr
        repeat-expr: num_labels
  label_entry:
    seq:
      - id: ofs_name
        type: u2
      - id: len_name
        type: u1
      - id: flags
        type: u1
      - id: ofs_value
        type: u2
      - id: len_value
        type: u2
  text:
    seq:
      - id: identifier_type
        type: u4
      - id: numeric_identifier
        type: u4
      - id: text
        type: strz
        size-eos: true
  index:
    seq:
      - id: index_entries
        type: index_entry
        repeat: eos
  index_entry:
    seq:
      - id: event_time_seconds
        type: u4
      - id: event_time_microseconds
        type: u4
      - id: archive_volume
        type: u4
      - id: ofs_meta
        type: u4
        doc: byte offset in .meta file of pmDesc or pmLogIndom
      - id: ofs_archive
        type: u4
        doc: byte offset in archive volume file of pmResult
enums:
  meta_records:
    1:
      id: description
    2:
      id: instance_domain
    3:
      id: label
    4:
      id: text
  label_types:
    1:
      id: context
    2:
      id: domain
    4:
      id: indom
    8:
      id: cluster
    16:
      id: item
    32:
      id: instances
