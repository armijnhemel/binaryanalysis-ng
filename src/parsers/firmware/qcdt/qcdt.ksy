meta:
  id: qcdt
  title: QCDT
  tags:
    - archive
    - android
  license: CC0-1.0
  endian: le
doc: |
  Format of Qualcomm DTB files. Note: the device entries can all point to
  the same entry as DTB files can be shared between devices.

doc-ref:
  - https://gitlab.com/Codeaurora/platform_system_core/-/raw/83b5d524c5/dtbtool/dtbtool.txt (v1)
  - https://raw.githubusercontent.com/omnirom/android_device_lge_g4-common/android-6.0/dtbtool/dtbtool.txt (v2)
  - https://raw.githubusercontent.com/CyanogenMod/android_device_qcom_common/cm-14.1/dtbtool/dtbtool.txt (v3)
  - https://source.codeaurora.org/quic/kernel/skales/plain/dtbTool?id=1.6.0
  - web.archive.org/web/20160402060151if_/https://developer.qualcomm.com/qfile/28821/lm80-p0436-1_little_kernel_boot_loader_overview.pdf (section 2.4.1)
seq:
  - id: magic
    contents: "QCDT"
  - id: version
    type: u4
    valid:
      any-of: [1, 2, 3]
  - id: num_dtbs
    type: u4
  - id: device_entries
    type: device_entry
    repeat: expr
    repeat-expr: num_dtbs
types:
  device_entry:
    seq:
      - id: platform_id
        type: u4
        enum: soc_ids
      - id: variant_id
        type: u4
      - id: subtype_id
        type: u4
        if: _root.version > 1
      - id: soc_revision
        type: u4
      - id: pmic0
        type: u4
        if: _root.version > 2
      - id: pmic1
        type: u4
        if: _root.version > 2
      - id: pmic2
        type: u4
        if: _root.version > 2
      - id: pmic3
        type: u4
        if: _root.version > 2
      - id: ofs_dtb
        type: u4
      - id: len_dtb
        type: u4
    instances:
      data:
        pos: ofs_dtb
        size: len_dtb
enums:
  soc_ids:
    71: msm8660
    87: msm8960
    109: apq8064
    122: msm8660a
    123: msm8260a
    124: apq8060a
    126: msm8974
    138: msm8960ab
    139: apq8060ab
    140: msm8260ab
    141: msm8660ab
    153: apq8064_prime
    178: apq8084
    184: apq8074
    185: msm8274
    186: msm8674
    194: msm8974_pro
    201: ipq8062
    202: ipq8064
    203: ipq8066
    206: msm8916
    207: msm8994
    208: apq8074_aa
    209: apq8074_ab
    210: apq8074_pro
    211: msm8274_aa
    212: msm8274_ab
    213: msm8274_pro
    214: msm8674_aa
    215: msm8674_ab
    216: msm8674_pro
    217: msm8974_aa
    218: msm8974_ab
    244: apq8064_au
    245: msm8909
    246: msm8996
    247: apq8016
    248: msm8216
    251: msm8992
    252: apq8092
    253: apq8094
    273: ipq4019
    291: apq8096
    292: msm8998
    305: msm8996sg
  platform_ids:
    1: cdp
    2: ffa
    3: fluid
    4: fusion
    5: oem
    6: qt
    7: mtp_mdm
    8: mtp
    9: liquid
    10: dragonboard
    11: qrd
    12: evb
    13: hrd
    14: dtv
    15: rumi
    16: virtio
    20: xpm
    21: rcm
    23: stp
    24: sbc
    29: cls
  pmic_ids:
    1: pm8941
    2: pm8841
    3: pm8019
    4: pm8026
    5: pm8110
    6: pma8084
    7: pmi8962
    8: pmd9635
    9: pm8994
    10: pmi8994
    11: pm8916
    12: pm8004
    13: pm8909
    14: pm2433
    15: pmd9655
    16: pm8950
    17: pmi8950
    18: pmk8001
    19: pmi8996
    20: pm8998
    21: pmi8998
    22: pm8953
    23: smb1380
    24: pm8005
    25: pm8937
