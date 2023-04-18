meta:
  id: mtk_secrom_info
  title: MediaTek Secure ROM info
  license: GPL-2.0
  endian: le
  encoding: UTF-8
doc-ref:
  - https://android.googlesource.com/kernel/mediatek/+/0164f13d76f1966b140ea06261ea6f63c073e080/drivers/misc/mediatek/masp/asf/asf_inc/sec_rom_info.h
seq:
  - id: sec_rom
    type: sec_rom
    size: 960
types:
  sec_rom:
    seq:
      - id: magic
        contents: ["AND_ROMINFO_v", 0, 0, 0]
      - id: version
        type: u4
        valid: 2
      - id: platform_id
        size: 16
      - id: project_id
        size: 16
      - id: sec_ro_exists
        type: u4
      - id: ofs_sec_ro
        type: u4
      - id: len_sec_ro
        type: u4
      - id: ofs_anti_clone
        type: u4
        valid: 0x54
      - id: len_anti_clone
        type: u4
        valid: 0xe0
      - id: ofs_sec_cfg
        type: u4
        #valid: 0x360000
      - id: len_sec_cfg
        type: u4
        #valid: 0x20000
      - id: reserved
        size: 128
      - id: sec_ctrl
        type: sec_ctrl
        size: 52
      - id: reserved_2
        size: 18
      - id: secure_boot_partitions
        size: 90
        type: secure_boot_partitions
      - id: sec_key
        size: 592
        type: sec_key
  sec_ctrl:
    seq:
      - id: name
        type: strz
        size: 16
      - id: version
        type: u4
      - id: usb_dl
        type: u4
      - id: boot
        type: u4
      - id: modem_auth
        type: u4
      - id: sds_en
        type: u4
      - id: ac_en
        size: 1
      - id: aes_legacy
        size: 1
      - id: secro_ac_en
        size: 1
      - id: sml_aes_key_ac_en
        size: 1
      - id: reserved
        size: 12
  secure_boot_partitions:
    seq:
      - id: name
        size: 10
        type: strz
        repeat: expr
        repeat-expr: 9
  sec_key:
    seq:
      - id: name
        #contents: ["AND_SECKEY_v", 0, 0, 0]
        size: 16
        type: strz
      - id: version
        type: u4
      - id: img_rsa_n
        size: 256
      - id: img_rsa_e
        size: 5
      - id: sml_aes_key
        size: 32
      - id: crypto_seed
        size: 16
      - id: sml_auth_rsa_n
        size: 256
      - id: sml_auth_rsa_e
        size: 5
