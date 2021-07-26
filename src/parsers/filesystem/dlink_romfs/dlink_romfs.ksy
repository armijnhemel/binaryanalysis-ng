meta:
  id: dlink_romfs
  title: D-Link ROMFS format
  license: GPL-2.0-or-later
  endian: le
  encoding: ASCII
doc: |
  File system used by D-Link in certain routers, such as DIR-600. This is
  apparently a modified version of the romfs file system used in eCos.
doc-ref:
  - https://raw.githubusercontent.com/ReFirmLabs/binwalk/ec47069/src/binwalk/plugins/dlromfsextract.py
  - http://web.archive.org/web/20201208093903/https://github.com/syschmod/dlink_patch_utils/wiki/D-Link-GO-RT-N150---vulnerabilities-and-firmware-modification
  - https://github.com/antmicro/ecos-openrisc/blob/0891c1c/packages/fs/rom/current/src/romfs.c
seq:
  - id: super_block
    type: super_block
    size: 32
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: super_block.num_entries
types:
  super_block:
    seq:
      - id: magic
        contents: "\x2emoR"
      - id: num_entries
        type: u4
      - id: unknown1
        type: u4
      - id: unknown2
        type: u4
      - id: signature
        type: signature
        size: 16
    doc-ref: https://github.com/antmicro/ecos-openrisc/blob/0891c1c/packages/fs/rom/current/src/romfs.c#L302
  signature:
    seq:
      - id: romfs_name
        contents: "ROMFS v"
      - id: version
        type: version
        size: 3
  version:
    seq:
      - id: major_version
        size: 1
        type: str
      - id: separator
        contents: "."
      - id: minor_version
        size: 1
        type: str
    instances:
      major:
        value: major_version.to_i
      minor:
        value: minor_version.to_i
  entry:
    seq:
      - id: entry_type
        type: u4
      - id: num_links
        type: u4
      - id: owner
        type: u2
      - id: group
        type: u2
      - id: len_entry
        type: u4
      - id: ctime
        type: u4
      - id: ofs_entry
        type: u4
      - id: len_decompressed
        type: u4 
        if: _root.super_block.signature.version.major == 9
      - id: entry_uid_block
        type:
          switch-on: _root.super_block.signature.version.major
          cases:
            1: entry_uid_block_v1
            9: entry_uid_block_v9
    doc-ref: https://github.com/antmicro/ecos-openrisc/blob/0891c1c/packages/fs/rom/current/src/romfs.c#L273
    instances:
     is_compressed:
       value: entry_type & 0x5b0000 == 0x5b0000
     is_directory:
       value: entry_type & 0x1 == 0x1
     is_data:
       value: entry_type & 0x8 == 0x8
     data:
       pos: ofs_entry
       size: len_entry
       type:
         switch-on: is_directory
         cases:
           true: dir_entries
  entry_uid_block_v1:
    seq:
      - id: open_bracket
        contents: ['<']
      - id: entry_uid
        size: 6
        type: str
      - id: closing_bracket
        contents: ['>']
  entry_uid_block_v9:
    seq:
      - id: entry_uid
        size: 4
        type: str
  dir_entries:
    seq:
      - id: dir_entries
        type: dir_entry
        repeat: eos
  dir_entry:
    seq:
      - id: directory_uid
        type: u4
      - id: next
        type: u4
      - id: entry_name
        type: strz
      - id: padding
        size: next - _parent._io.pos
