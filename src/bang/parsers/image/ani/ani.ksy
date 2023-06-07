meta:
  id: ani
  title: Microsoft Animated Cursor Format
  file-extension:
    - ani
  xref:
    justsolve:
      - ANI
    mime:
      - application/x-navi-animation
    pronom:
      - fmt/386
    rfc: 2361
    wikidata:
      - Q295711
  tags:
    - windows
  license: BSD-3-Clause-Attribution
  imports:
    - /common/riff
  encoding: ASCII
  endian: le
doc: |
  This Kaitai implementation was adapted from the WAV Kaitai implementation,
  which was written by John Byrd of Gigantic Software
  (jbyrd@giganticsoftware.com), and it is likely to contain bugs.
seq:
  - id: chunk
    type: 'riff::chunk'
instances:
  chunk_id:
    value: chunk.id
    enum: fourcc
  is_riff_chunk:
    value: 'chunk_id == fourcc::riff'
  parent_chunk_data:
    io: chunk.data_slot._io
    pos: 0
    type: 'riff::parent_chunk_data'
    if: is_riff_chunk
  form_type:
    value: parent_chunk_data.form_type
    enum: fourcc
  is_form_type_ani:
    value: 'is_riff_chunk and form_type == fourcc::acon'
  subchunks:
    io: parent_chunk_data.subchunks_slot._io
    pos: 0
    type: chunk_type
    repeat: eos
    if: is_form_type_ani
types:
  dummy:
    seq:
      - id: dummy_id
        type: riff
  chunk_type:
    seq:
      - id: chunk
        type: 'riff::chunk'
    instances:
      chunk_id:
        value: chunk.id
        enum: fourcc
      chunk_data:
        io: chunk.data_slot._io
        pos: 0
        type:
          switch-on: chunk_id
          cases:
            'fourcc::data': data_chunk_type
            'fourcc::list': list_chunk_type

  list_chunk_type:
    seq:
      - id: parent_chunk_data
        type: 'riff::parent_chunk_data'
    instances:
      form_type:
        value: parent_chunk_data.form_type
        enum: fourcc
      subchunks:
        io: parent_chunk_data.subchunks_slot._io
        pos: 0
        type:
          switch-on: form_type
          cases:
            'fourcc::info': info_chunk_type
        repeat: eos

  info_chunk_type:
    seq:
      - id: chunk
        type: 'riff::chunk'
    instances:
      chunk_data:
        io: chunk.data_slot._io
        pos: 0
        type: strz

  data_chunk_type:
    seq:
      - id: data
        size-eos: true
enums:
  fourcc:
    # little-endian
    0x46464952: riff
    0x4e4f4341: acon
    0x4e4f4349: icon
    0x4f464e49: info
    0x5453494c: list
    0x61746164: data
    0x68696e61: anih
    0x65746172: rate
    0x20716573: seq
