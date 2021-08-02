meta:
  id: ubifs
  title: UBIFS
  license: GPL-2.0-only
  endian: le
  encoding: UTF-8
doc-ref: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ubifs/ubifs-media.h
seq:
  - id: leb0
    size: super.node_contents.leb_size
    doc: LEB0 contains the superblock
  - id: leb1
    size: super.node_contents.leb_size
    doc: LEB1 contains a copy of the master block
  - id: leb2
    size: super.node_contents.leb_size
    doc: LEB2 contains a copy of the master block
  - id: lebs
    size: super.node_contents.leb_size
    repeat: expr
    repeat-expr: super.node_contents.num_leb - 3
instances:
  super:
    pos: 0
    type: superblock_node
types:
  superblock_node:
    seq:
      - id: header
        type: common_header
      - id: node_contents
        size: header.len_full_node - header._sizeof
        type: superblock
  common_header:
    seq:
      - id: magic
        type: u4
        valid: 0x06101831
        doc: UBIFS node magic number (%UBIFS_NODE_MAGIC)
      - id: crc
        type: u4
        doc: CRC-32 checksum of the node header
      - id: sequence_number
        -orig-id: sqnum
        type: u8
        doc: sequence number
      - id: len_full_node
        -orig-id: len
        type: u4
        doc: full node length
      - id: node_type
        type: u1
        doc: node type
        enum: node_types
      - id: group_type
        type: u1
        doc: node group type
      - id: padding
        size: 2
        contents: [0x00, 0x00]
        doc: reserved for future, zeroes
  superblock:
    seq:
      - id: padding1
        size: 2
        contents: [0x00, 0x00]
        doc: reserved for future, zeroes
      - id: key_hash
        type: u1
        doc: type of hash function used in keys
      - id: key_fmt
        type: u1
        doc: format of the key
      - id: flags
        type: u4
        doc: file-system flags (%UBIFS_FLG_BIGLPT, etc)
      - id: min_io_size
        type: u4
        doc: minimal input/output unit size
      - id: leb_size
        type: u4
        doc: logical eraseblock size in bytes
      - id: num_leb
        -orig-id: leb_cnt
        type: u4
        doc: count of LEBs used by file-system
      - id: max_leb_cnt
        type: u4
        doc: maximum count of LEBs used by file-system
      - id: max_bud_bytes
        type: u8
        doc: maximum amount of data stored in buds
      - id: log_lebs
        type: u4
        doc: log size in logical eraseblocks
      - id: lpt_lebs
        type: u4
        doc: number of LEBs used for lprops table
      - id: orph_lebs
        type: u4
        doc: number of LEBs used for recording orphans
      - id: jhead_cnt
        type: u4
        doc: count of journal heads
      - id: fanout
        type: u4
        doc: tree fanout (max. number of links per indexing node)
      - id: lsave_cnt
        type: u4
        doc: number of LEB numbers in LPT's save table
      - id: fmt_version
        type: u4
        doc: UBIFS on-flash format version
      - id: default_compression
        -orig-id: default_compr
        type: u2
        enum: compression
      - id: padding2
        size: 2
        contents: [0x00, 0x00]
        doc: reserved for future, zeroes
      - id: reserve_pool_uid
        -orig: rp_uid
        type: u4
        doc: reserve pool UID
      - id: reserve_pool_gid
        -orig: rp_gid
        type: u4
        doc: reserve pool GID
      - id: reserve_pool_size
        type: u8
        doc: size of the reserved pool in bytes
      - id: time_granularity
        type: u4
        doc: time granularity in nanoseconds
      - id: uuid
        size: 16
        doc: UUID generated when the file system image was created
      - id: ro_compat_version
        type: u4
        doc: UBIFS R/O compatibility version
      - id: hmac
        size: 64
        doc: HMAC to authenticate the superblock node
      - id: hmac_wkm
        size: 64
        doc: |
          HMAC of a well known message (the string "UBIFS") as a convenience
          to the user to check if the correct key is passed
      - id: hash_algo
        type: u2
        doc: The hash algo used for this filesystem (one of enum hash_algo)
      - id: hash_mst
        size: 64
        doc: |
          hash of the master node, only valid for signed images in which the
          master node does not contain a hmac
      - id: padding3
        type: padding_byte
        repeat: expr
        repeat-expr: 3774
  inode:
    seq:
      - id: key
        size: 16
        doc: node key
      - id: sequence_number
        -orig-id: creat_sqnum
        type: u8
        doc: sequence number at time of creation
      - id: len_uncompressed
        -orig-id: size
        type: u8
        doc: inode size in bytes (amount of uncompressed data)
      - id: atime_sec
        type: u8
        doc: access time seconds
      - id: ctime_sec
        type: u8
        doc: creation time seconds
      - id: mtime_sec
        type: u8
        doc: modification time seconds
      - id: atime_nsec
        type: u4
        doc: access time nanoseconds
      - id: ctime_nsec
        type: u4
        doc: creation time nanoseconds
      - id: mtime_nsec
        type: u4
        doc: modification time nanoseconds
      - id: num_links
        -orig-id: nlink
        type: u4
        doc: number of hard links
      - id: uid
        type: u4
        doc: owner ID
      - id: gid
        type: u4
        doc: group ID
      - id: mode
        type: u4
        doc: access flags
      - id: flags
        type: u4
        doc: per-inode flags (%UBIFS_COMPR_FL, %UBIFS_SYNC_FL, etc)
      - id: len_data
        -orig-id: data_len
        type: u4
        doc: inode data length
      - id: xattr_cnt
        type: u4
        doc: count of extended attributes this inode has
      - id: xattr_size
        type: u4
        doc: summarized size of all extended attributes in bytes
      - id: padding1
        size: 4
        contents: [0x00, 0x00, 0x00, 0x00]
      - id: xattr_names
        type: u4
        doc: |
          sum of lengths of all extended attribute names belonging
          to this inode
      - id: compression
        -orig-type: compr_type
        type: u2
        enum: compression
        doc: compression type used for this inode
      - id: padding2
        type: padding_byte
        repeat: expr
        repeat-expr: 26
        doc: reserved for future, zeroes
      - id: data
        size: len_data
        doc: data attached to the inode
  directory:
    seq:
      - id: key
        size: 16
        doc: node key
      - id: inode_number
        -orig-id: inum
        type: u8
        doc: target inode number
      - id: padding1
        contents: [0x00]
        doc: reserved for future, zeroes
      - id: inode_type
        -orig-id: type
        type: u1
        enum: inode_types
        doc: type of the target inode (%UBIFS_ITYPE_REG, %UBIFS_ITYPE_DIR, etc)
      - id: len_name
        -orig-id: nlen
        type: u2
        doc: name length
      - id: cookie
        type: u4
        doc: A 32bits random number, used to construct a 64bits identifier.
      - id: name
        type: strz
        size: len_name
        doc: zero-terminated name
  padding_byte:
    seq:
      - id: padding
        contents: [0x00]
enums:
  compression:
    0:
      id: no_compression
      -orig-id: UBIFS_COMPR_NONE
      doc: no compression
    1:
      id: lzo
      -orig-id: UBIFS_COMPR_LZO
      doc: LZO compression
    2:
      id: zlib
      -orig-id: UBIFS_COMPR_ZLIB
      doc: zlib compression
    3:
      id: zstd
      -orig-id: UBIFS_COMPR_ZSTD
      doc: zstd compression
  inode_types:
    0: 
      id: regular
      -orig-id: UBIFS_ITYPE_REG
      doc: regular file
    1:
      id: directory
      -orig-id: UBIFS_ITYPE_DIR
      doc: directory
    2:
      id: link
      -orig-id: UBIFS_ITYPE_LNK
      doc: soft link
    3:
      id: block_device
      -orig-id: UBIFS_ITYPE_BLK
      doc: block device node
    4:
      id: character_device
      -orig-id: UBIFS_ITYPE_CHR
      doc: character device node
    5:
      id: fifo
      -orig-id: UBIFS_ITYPE_FIFO
      doc: fifo
    6:
      id: socket
      -orig-id: UBIFS_ITYPE_SOCK
      doc: socket
  node_types:
    0:
      id: inode
      -orig-id: UBIFS_INO_NODE
      doc: inode node
    1: 
      id: data
      -orig-id: UBIFS_DATA_NODE
      doc: data node
    2:
      id: directory
      -orig-id: UBIFS_DENT_NODE
      doc: directory entry node
    3:
      id: extended_attribute
      -orig-id: UBIFS_XENT_NODE
      doc: extended attribute node
    4:
      id: truncation
      -orig-id: UBIFS_TRUN_NODE
      doc: truncation node
    5:
      id: padding
      -orig-id: UBIFS_PAD_NODE
      doc: padding node
    6:
      id: superblock
      -orig-id: UBIFS_SB_NODE
      doc: superblock node
    7:
      id: master
      -orig-id: UBIFS_MST_NODE
      doc: master node
    8:
      id: reference
      -orig-id: UBIFS_REF_NODE
      doc: LEB reference node
    9:
      id: index
      -orig-id: UBIFS_IDX_NODE
      doc: index node
    10:
      id: commit_start
      -orig-id: UBIFS_CS_NODE
      doc: commit start node
    11:
      id: orphan
      -orig-id: UBIFS_ORPH_NODE
      doc: orphan node
    12:
      id: authentication
      -orig-id: UBIFS_AUTH_NODE
      doc: authentication node
    13:
      id: signature
      -orig-id: UBIFS_SIG_NODE
      doc: signature node
