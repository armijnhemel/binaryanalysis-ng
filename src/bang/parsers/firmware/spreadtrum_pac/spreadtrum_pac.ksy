meta:
  id: spreadtrum_pac
  title: Spreadtrum Pac
  license: CC-1.0
  encoding: UTF-8
  endian: le
doc-ref: https://github.com/divinebird/pacextractor/blob/master/pacextractor.c
seq:
  - id: header
    type: header
instances:
  entries:
    pos: header.ofs_partitions_list
    type: entries(header.num_partitions)
types:
  header:
    seq:
      - id: unknown1
        size: 48
      - id: len_file
        type: u4
      - id: product_name
        size: 512
      - id: firmware_name
        size: 512
      - id: num_partitions
        type: u4
        valid:
          max: _root._io.size
          # TODO: this check can probably be tighter
      - id: ofs_partitions_list
        -orig-id: partitionsListStart
        type: u4
      - id: unknown3
        size: 20
      - id: product_name2
        size: 100
      - id: unknown4
        size: 12
      - id: unknown5
        size: 4
  entries:
    params:
      - id: num_partitions
        type: u4
    seq:
      - id: entries
        type: entry
        repeat: expr
        repeat-expr: num_partitions
  entry:
    seq:
      - id: header
        type: entry_header
      - id: padding
        size: header.len - header._sizeof
    instances:
      data:
        pos: header.ofs_partition
        size: header.len_partition
        io: _root._io
  entry_header:
    seq:
      - id: len
        type: u4
      - id: name
        size: 512
        #type: strz
        #encoding: UTF-16-LE
      - id: file_name
        size: 1024
        #type: strz
        #encoding: UTF-16-LE
      - id: len_partition
        -orig-id: partitionSize
        type: u4
      - id: unknown1
        size: 8
      - id: ofs_partition
        -orig-id: partitionAddrInPac
        type: u4
      - id: unknown2
        size: 12
