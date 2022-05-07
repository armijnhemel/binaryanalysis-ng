# Firmware test notes

Some random notes detailing downloaded firmware files, including CPU, which
file format is used, etc.

## FW_RT1800_V1.1.00.015_Prod_20210611_code.bin

Belkin RT1800, uses FIT images (device tree).

## FW_BRT_AC828__30043807587.zip

Uses `u-boot`, `squashfs`

## FW_DSL-AC51_1123858.zip

Uses `lzma` compressed kernel, `squashfs`.

## FW_GS_AX3000_300438643406.zip

ASUS ROG Strix GS-AX3000, uses `ubi`, `squashfs`.

## FW_GT_AX11000_30043845252.zip

ASUS ROG Rapture GT-AX11000, uses ubifs.

## FW_GT_AXE11000_300438643986.zip

Uses `ubi`, `ubifs`, `lzma` compressed kernel. Uses `ipk` files.

## FW_RP_AC87_300438218537.ZIP

Uses `u-boot`, `lzma` compressed kernel, `squashfs`.

## FW_RT1800_V1.1.00.015_Prod_20210611_code.bin

Uses `dtb` FIT image, `squashfs`

## FW_RT_AC3200_30043807266.ZIP

ASUS RT-AC3200, uses `trx` and `squashfs`. Uses `ipk` files.

## FW_RT_AC55UHP_300438250702.ZIP

ASUS RT-AC55UHP, uses `u-boot`, `lzma` compressed kernel, `ipk` files.

## FW_RT_AX53U_300438244917.zip

Uses `dtb` FIT image, `squashfs`, `ipk` files.

## FW_RX7500_1.0.04.141_prod.bin

Uses `dtb` FIT image, `ubi`, `squashfs`

## FW_ZENWIFI_XD4_300438643129.zip

Uses `ubi`, `ubifs`, `lzma` compressed kernel

## FW_ZENWIFI_XT8_300438643170.zip

Uses `ubi`, `squashfs`, `lzma` compressed kernel, uses `ipk` files.

## Tinker_Edge_T-Mendel-Chef-V1.0.0-20200221.zip

Uses `androidsparse`

## EAX80-V1.0.1.70_1.0.2.zip

Uses `jffs2`, `ubi`, `squashfs`

## ECS1008P-1112FP_FWv1.1.40_20201008.zip

MIPS based (Realtek 83xx). Uses `tar`, `u-boot` (BIX variant)

## IC-3210W_3.05.zip

MIPS based. Uses `u-boot`, `xz`, `cpio`

## FWA119S.bin

Novatek based dashcam firmware, probably using eCos

## IC-9110W_V2_3.03.zip

Edimax camera (IC-9110W v2), using `u-boot`, `cpio`, `lzma`, `xz`.

## BR6435ND_EdimaxOBML_1.12_upg.zip

Edimax device, uses `u-boot`, `squashfs`, `lzma`

## https://github.com/mrdoob/three.js.git

Contains test files for ktx

## 20080929182630500_MX10_Firmware.zip

Contains `bflt` test files.

## productattachments_files_f_i_fi8908w_firmware_11.14.1.46.zip

From <https://www.foscam.nl/attachments/FI8908W_Firmware>

Contains `bflt` test files (including `gzip` compressed).
