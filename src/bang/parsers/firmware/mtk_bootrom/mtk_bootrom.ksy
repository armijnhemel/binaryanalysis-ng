meta:
  id: mtk_bootrom
  title: MediaTek BootROM format
  license: GPL-2.0-or-later
  endian: le
  encoding: UTF-8
doc-ref:
  - https://source.denx.de/u-boot/u-boot/-/blob/a0953b34d9d8d9309c3eabbb75746fef66b15ffe/tools/mtk_image.h
  - https://source.denx.de/u-boot/u-boot/-/blob/a0953b34d9d8d9309c3eabbb75746fef66b15ffe/tools/mtk_image.c
seq:
  - id: file_info_header
    type: common_header
  - id: file_info_data
    size: file_info_header.len_data - file_info_header._sizeof
    type: file_info
  - id: bl_info_header
    type: common_header
  - id: bl_info_data
    size: bl_info_header.len_data - bl_info_header._sizeof
    type: bl_info
  - id: brom_config_header
    type: common_header
  - id: brom_config_data
    size: brom_config_header.len_data - brom_config_header._sizeof
    type: brom_config
  - id: bl_security_key_header
    type: common_header
  - id: bl_security_key_data
    size: bl_security_key_header.len_data - bl_security_key_header._sizeof
    type: bl_security_key
  - id: anti_clone_header
    type: common_header
  - id: anti_clone_data
    size: anti_clone_header.len_data - anti_clone_header._sizeof
    type: anti_clone
  - id: brom_security_config_header
    type: common_header
  - id: brom_security_config_data
    size: brom_security_config_header.len_data - brom_security_config_header._sizeof
    type: brom_security_config
types:
  common_header:
    seq:
      - id: magic
        contents: "MMM"
      - id: version
        type: u1
      - id: len_data
        -orig-id: size
        type: u2
      - id: bootrom_type
        -orig-id: type
        type: u2
        enum: bootrom_type
        valid:
          any-of:
            - bootrom_type::anti_clone
            - bootrom_type::bl_info
            - bootrom_type::bl_security_key
            - bootrom_type::brom_config
            - bootrom_type::brom_security_config
            - bootrom_type::file_info
  anti_clone:
    seq:
      - id: ac_b2k
        type: u1
      - id: ac_b2c
        type: u1
      - id: padding
        size: 2
      - id: ofs_anti_clone
        -orig-id: ac_offset
        type: u1
      - id: len_anti_clone
        -orig-id: ac_len
        type: u1
  bl_info:
    seq:
      - id: attr
        type: u4
  bl_security_key:
    seq:
      - id: key
        size: 524
  brom_config:
    seq:
      - id: config_bits
        -orig-id: cfg_bits
        type: u4
      - id: usbdl_by_auto_detect_timeout_ms
        -orig-id: usbdl_by_auto_detect_timeout_ms
        type: u4
      - id: unused1
        size: 69
      - id: jump_bl_arm64
        type: u1
      - id: unused2
        size: 2
      - id: usbdl_by_kcol0_timeout_ms
        type: u4
      - id: usbdl_by_flag_timeout_ms
        type: u4
      - id: pad
        size: 4
  brom_security_config:
    seq:
      - id: configuration
        -orig-id: cfg_bits
        type: u4
      - id: customer_name
        size: 32
      - id: pad
        size: 4
    instances:
      jtag_enabled:
        value: configuration & 0x01 == 0x01
      uart_enabled:
        value: configuration & 0x02 == 0x02
  file_info:
    seq:
      - id: name
        type: strz
        size: 12
      - id: unused
        size: 4
      - id: file_type
        type: u2
      - id: flash_type
        type: u1
      - id: signature_type
        type: u1
        # enum: signature_types
        # TODO: there are files where this is 3 and not 0 or 1
      - id: load_address
        type: u4
      - id: total_size
        type: u4
      - id: max_size
        type: u4
      - id: header_size
        type: u4
      - id: signature_size
        type: u4
      - id: jump_offset
        type: u4
      - id: processed
        type: u4
enums:
  bootrom_type:
    0:
      id: file_info
      -orig-id: GFH_TYPE_FILE_INFO
    1:
      id: bl_info
      -orig-id: GFH_TYPE_BL_INFO
    2:
      id: anti_clone
      -orig-id: GFH_TYPE_ANTI_CLONE
    3:
      id: bl_security_key
      -orig-id: GFH_TYPE_BL_SEC_KEY
    7:
      id: brom_config
      -orig-id: GFH_TYPE_BROM_CFG
    8:
      id: brom_security_config
      -orig-id: GFH_TYPE_BROM_SEC_CFG
  signature_types:
    0: no_signature
    1: sha256
