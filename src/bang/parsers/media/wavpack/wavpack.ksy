meta:
  id: wavpack
  title: WavPack
  xref:
    wikidata: Q544812
  license: CC0-1.0
  ks-version: 0.9
  endian: le
doc-ref:
  - https://www.wavpack.com/WavPack5FileFormat.pdf

seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: chunk_id
        contents: 'wvpk'
      - id: len_header
        type: u4
      - id: rest_of_header
        size: len_header - len_header._sizeof - chunk_id._sizeof
        type: rest_of_header
    types:
      rest_of_header:
        seq:
          - id: version
            type: u2
          - id: block_index_upper_8_bits
            type: u1
          - id: total_samples_upper_8_bits
            type: u1
          - id: total_samples_lower_32_bits
            type: u4
          - id: block_index_lower_32_bits
            type: u4
          - id: num_block_samples
            type: u4
          - id: flags
            type: u4
          - id: crc
            type: u4
        instances:
          block_index:
            value: (block_index_upper_8_bits << 32) + block_index_lower_32_bits
          total_samples:
            value: (total_samples_upper_8_bits << 32) + total_samples_lower_32_bits
