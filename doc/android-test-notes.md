# Android test notes

Some random notes detailing downloaded firmware files, including CPU, which
file format is used, etc.

# Official Android images

The following files were downloaded from the official Android OTA/factory
image websites:

* <https://developers.google.com/android/ota>
* <https://developers.google.com/android/images>

## angler-mda89d-factory-9f001626.zip

The Nexus 6P (codename "angler") was made by Huawei. Firmware uses the
`androidboothuawei` format and the `android_boot_img` version 0 format.

## barbet-ota-rd2a.210605.006-e56baaf5.zip

The Pixel 5a (codename "barbet") uses the Chrome update file format
(version 2). It uses Dex 035 and 039, Art 085, Vdex 021 and Oat 183.

## fugu-lrx21m-factory-e012394c.zip

The Nexus Player (codename "fugu") was made by ASUS. The firmware uses
the `androidasusboot` format and the `android_boot_img` version 0 format.
Uses OAT 039.

## hammerhead-krt16m-factory-fb4041cc.zip

The Nexus 5 (codename "hammerhead") was made by LG. The firmware uses the
`androidmsmboot` format and the `android_boot_img` version 0 format. Uses
Odex 036 and regular Dex 035.

## oriole-sp2a.220405.004-factory-f560807e.zip

Android 12L uses the `android_fbpk` version 1 and version 2 format,
`android_vendor_boot` version 4 and `android_boot_img` version 4. It uses
Oat 199, Art 099, Vdex 027, Dex 035, Dex 038 and Dex 039.

## raven-sd1a.210817.015.a4-factory-bd6cb030.zip

The Pixel 6 Pro uses the `android_fbpk` version 1 and version 2 format,
`android_vendor_boot` version 4 and `android_boot_img` version 4. It uses
Art 099, Oat 195, Vdex 027, Dex 035, Dex 038 and Dex 039.

## razorg-JLS36C-factory-834eab41.zip

The Nexus 7 2013 Mobile (codename "razorg") was made by ASUS. The firmware
uses `androidasusboot` format. It uses Odex 036 and regular Dex 035.

## redfin-rd1a.200810.020-factory-c3ea1715.zip

The Pixel 5 (codename "redfin") was made by Google based on a Qualcomm chip.
It uses the `android_fbpk` version 1 format, the `android_vendor_boot`
format and the `android_boot_img` version 3. It uses Dex 039, Vdex 021,
Art 085 and Oat 183. It contains Android verified boot (`avb`) images.
Contains `acdb` files.

## sailfish-nde63h-factory-43ba5f81.zip

The Pixel (codename "sailfish") was made by HTC. It uses the `androidbootmsm`
format. It uses Oat 079, Dex 035 and Dex 037.

## shamu-lrx21o-factory-ef423ec5.zip

The Nexus 6 (codename "shamu") was made by Motorola Mobility. It uses the
`android_boot_img` version 0 format. It uses Oat 039.

## soju-grk39f-factory-8e283784.zip

The Nexus S (codename "crespo") was made by Samsung. It uses the `android_boot_img`
version 0 format and Dex 035 and Odex 036.

## walleye-opm1.171019.011-factory-f74dd4fd.zip

The Pixel 2 (codename "walleye") was made by HTC. it uses the `androidbootmsm`
format. It uses Dex 037, Vdex 010 and Oat 131.

# walleye-ppr1.180610.009-factory-4149f7e5.zip

The Pixel 2 (codename "walleye") was made by HTC. it uses the `androidbootmsm`.
It uses Dex 035, Dex 038, Dex 039, Vdex 019 and Oat 138.

# ROM rebuilds

Some test files are from ROM rebuilds

## omni-7.1.2-20171120-flounder-WEEKLY.zip

From <https://dl.omnirom.org/flounder/>. Uses the `android_boot_img`
version 0 format. It uses Dex 035 and Dex 037.

## twrp-3.3.1-0-h870.img

From <https://dl.twrp.me/h870/>. Uses the `android_boot_img` version 0 format
and Dex 035.

## twrp-3.3.1-0-marlin.img

From <https://dl.twrp.me/marlin/>. Uses the `android_boot_img` version 0 format
and Dex 035.

# Official firmware files

## htc_d027_9_7inch_wm3732_phonesdk_gc2035_gc0308_de_201210122.img

Rockchip based, uses `rk_crc`, `rockchip` and `android_boot_img` version 0
formats. Uses Dex 035 and Dex 036 (which officially doesn't exist).

## I9300XXUFMB3_I9300OJKFMB3_ILO.zip

Uses Dex 035 and Odex 036.

## 7_inch_android1-5_18506_infotmic_X210_2.3.3.zip

Infotmic m799ca based device. Uses Dex 035 and U-Boot.

## OS_Acer_3.003.01.EMEA.CUS1EN_A21E_A.zip

Acer BeTouch E130, uses the `nb0` format. The ZIP file contains an MSI file
called `Acer E130 Tool Setup.msi` which can be unpacked with `7z`. Inside
there is a CAB file called `_D73E97C33A4BA86CBC3B146ECFF38C2C` which can be
unpacked with `cabextract` and which contains a file called
`_B8D67569E4EF4C3386C854FEE4260157` which is the actual firmware file.

# Random files

Most of the files below were downloaded from obscure firmware download sites,
which I will not link to. Some of these were repacked from the original and
might have been modified.

## Alcatel_OneTouch_991D_MT6573_Arabic_150415.zip

Uses `yaffs2`, `android_boot_img` version 0, Dex 035.

## Allfine10 Joy RK3066.zip

Uses `rockchip`, `rk_crc`, `android_boot_img` version 0, Dex 035 and (withdrawn) Dex 036

## Allwinner_A23_T739_Mainboard_V2.2_JTX.zip

Uses `android_boot_img` version 0, but `extra_cmdline` isn't asciiz.

## BQ_Aquaris_E4.5_2.0.1_20150623_1900_MT6582.zip

Mediatek MT6582 based, uses `mtk_bootrom`, `android_boot_img` version 0, `androidsparse`, Dex 035.

## Dimo_Soren_2S_MT6572_20140108_4.2.2.zip

Mediatek MT6572 based, uses Dex 035 and Odex 036.

## Eurostar_Onyx_1_Plus_MT6580_06262017_6.0.zip

Mediatek MT6580 based, uses `mtk_bootrom` amongst others. Uses `android_mediatek_logo`.

## fw-vendor_phoenix_miui_PHOENIX_20.9.3_cf0b9e25cc_10.0.zip

Qualcomm MSM8916 based, uses `android_sparse_data` with Brotli compression.

## Gretel_A6_MT6737M_6.0.zip

Mediatek MT6737M based device. Uses `android_boot_img` version 0, Dex 035 and Oat 064.

## LYF_Jio_F271i_000-01-09-230818_SPD.zip

Spreadtrum based, uses `spreadtrum_pac`

## MD_LIFETAB_P9514.20111201.245-signed-ota-update-20111201040042.zip

Based on NVidia Tegra. Uses Dex 035 and Odex 036.

## Nokia5_Android_7.1.2_October2017_Update.zip

Qualcomm MSM8937 based, uses `android_sparse_data` but a newer format using
bsdiff and imgdiff.

## Odys_Loox_Update_1205.zip

Rockchip based, uses cramfs. Uses `rk_crc` format, Dex 035 and Odex 036.

## Okapia_Shopno_SP7731GEA_V05_20160331_5.1_SPD.zip

Spreadtrum based, uses `spreadtrum_pac`

## Opsson_Q1_07222014_4.3_QFIL.zip

Qualcomm MSM8926 based, seems to need QFIL and data first needs to be reconstructed.

## Qmobile_QTab_V1_Plus_20170531_RC.zip

Allwinner based, uses the `allwinner_img` file format.

## Sansui_U40_Plus_V2.0_12062015.zip

Spreadtrum based, uses `spreadtrum_pac`

## Titan_8_Plus_MT6572_20180126_4.4.2.zip

Mediatek MT6572 based, uses `mtk_bootrom` amongst others.

## Vega_Tab_67_C543G_MT6572_16122016.zip

Mediatek MT6572 based, uses Dex 035. Has a weirdly formatted ext4 file system that
is smaller than declared.

## Vertex_Sun_MT6737M_20171214_7.0.zip

Mediatek MT6737M based, uses `mtk_bootrom` amongst others.

## Verykool_S5014_VK_Generic_Dual_SW_1.6_4.4.2.zip

Mediatek MT6582 based, uses `mtk_bootrom` amongst others.

## Winstar_W37_150301_020637_4.2.2.zip

Mediatek MT6572 based, uses UBI/ubifs, with a volume table at the end
of the image.

## Winstar_S5_SP7731GEA_V03_20161027_6.0.zip

Spreadtrum based, uses `spreadtrum_pac`

## Xolo_Q700S_Plus_S004_05082014.zip

Mediatek MT6582 based, uses `mtk_bootrom` amongst others.

## Zopo_8510_MIUI_MT6592_20140328_4.2.2.zip

Mediatek MT6592 based, uses `mtk_bootrom` amongst others. Also uses
Mediatek's own `jex` file format, which is used for some files like
`/framework/mediatek-common.jar.jex`. There is also a separate `dex2jex`
program, which seems to indicate that some Dex files are first transformed
into another format, which is then stored in an ELF file, similar to what
regular Android does with `oat`.

There is no documentation for the `jex` file format.

# Kind of Android

Some files are partial Android or regular Linux devices with support
for some Android things.

## FANTEC_3DFHDL_Firmware_Android_20121128-v10.1.11_r9757.zip

Realtek based device. Uses yaffs2 and Dex 035.
