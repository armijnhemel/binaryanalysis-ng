meta:
  id: spreadtrum_pac
  title: Spreadtrum Pac
  license: CC-1.0
  encoding: UTF-8
  endian: le
doc-ref:
  - https://github.com/divinebird/pacextractor/blob/master/pacextractor.c
  - https://github.com/yonglongliu/vendor/blob/f0e4a4c5025b8f7a13e69db3af9446717702f4f2/sprd/build/buildpac/tools/unpac_perl/unpac.pl#L145
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
      - id: version
        size: 48
      - id: len_file
        type: u4
        valid:
          min: 2124
          max: _root._io.size
      - id: product_name
        size: 512
      - id: firmware_name
        size: 512
      - id: num_partitions
        type: u4
        valid:
          min: 1
          max: _root._io.size
          # TODO: this check can probably be tighter
      - id: ofs_partitions_list
        -orig-id: partitionsListStart
        type: u4
        valid:
          min: 2124
          max: _root._io.size
      - id: mode
        type: u4
      - id: flash_type
        type: u4
      - id: nand_strategy
        type: u4
      - id: is_nv_backup
        type: u4
      - id: nand_page_type
        type: u4
      - id: product_name2
        size: 200
      - id: oma_dm_product_flag
        type: u4
      - id: is_oma_dm
        type: u4
      - id: is_preload
        type: u4
      - id: reserved
        type: padding4
        repeat: expr
        repeat-expr: 200
        #size: 800
      - id: magic
        contents: [0xfa, 0xff, 0xfa, 0xff]
      - id: crc1
        type: u2
      - id: crc2
        type: u2
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
        valid:
          max: _root._io.size
        type: u4
      - id: file_flag
        type: u4
      - id: check_flag
        type: u4
      - id: ofs_partition
        -orig-id: partitionAddrInPac
        type: u4
        valid:
          max: _root._io.size
      - id: omit_flag
        type: u4
      - id: addr_num
        type: u4
      - id: addresses
        type: u4
        repeat: expr
        repeat-expr: 5
      - id: reserved
        size: 996
  padding4:
    seq:
      - id: padding
        contents: [0x00, 0x00, 0x00, 0x00]
