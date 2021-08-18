# Android test notes

Some random notes detailing downloaded firmware files, including CPU, which
file format is used, etc.

Most of these files were downloaded from obscure firmware download sites,
which I will not link to.

## Eurostar_Onyx_1_Plus_MT6580_06262017_6.0.zip

Mediatek MT6580 based, uses `mtk_bootrom` amongst others.

## fw-vendor_phoenix_miui_PHOENIX_20.9.3_cf0b9e25cc_10.0.zip

Qualcomm MSM8916 based, uses `android_sparse_data` with Brotli compression.

## LYF_Jio_F271i_000-01-09-230818_SPD.zip

Spreadtrum based, uses `spreadtrum_pac`

## Nokia5_Android_7.1.2_October2017_Update.zip

Qualcomm MSM8937 based, uses `android_sparse_data` but a newer format using
bsdiff and imgdiff.

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

Mediatek MT6592 based, uses `mtk_bootrom` amongst others.
