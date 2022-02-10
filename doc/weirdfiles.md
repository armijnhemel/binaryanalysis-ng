# Firmware files

## `M-7310_(EU)_V1_160301.zip`

TP-Link firmware, contains non-standard Broadcom TRX file `fw.bin.trx`

File seen on some media device, needing an unknown ZIP version:

    $ file Plex_5.5.0.227.apk
    Plex_5.5.0.227.apk: Zip archive data, at least v?[0] to extract

This file also has an Android signing block, but does not use data descriptors

## G800F.zip

Samsung Galaxy S5 mini.

There is a library `libSmartVolumeLib.so` that has very weird ELF data (output from `readelf`):

    0x00000001 (NEEDED)      Shared library: [D:/__00_Development/workspace/__Audio_Solution_Lib/SmartVolumeLib_ver2.2c_<BC><F6><C1><A4><C1><DF>//jni/lib/libsavsac.so]
    0x00000001 (NEEDED)      Shared library: [D:/__00_Development/workspace/__Audio_Solution_Lib/SmartVolumeLib_ver2.2c_<BC><F6><C1><A4><C1><DF>//jni/lib/libsavscmn.so]
    0x00000001 (NEEDED)      Shared library: [D:/__00_Development/workspace/__Audio_Solution_Lib/SmartVolumeLib_ver2.2c_<BC><F6><C1><A4><C1><DF>//jni/lib/libsavsff.so]


# PNG

Interesting test PNG with GPS data:

<https://github.com/xbgmsharp/piwigo-openstreetmap/issues/14>

iPhone "optimized" PNG files that are not valid PNG files:

<http://www.jongware.com/pngdefry.html>
<https://pmt.sourceforge.io/pngcrush/>

Image test suite for PNGs
<https://code.google.com/archive/p/imagetestsuite/downloads>

<https://stackoverflow.com/questions/4242402/the-fireworks-png-format-any-insight-any-libs>
<https://commons.wikimedia.org/wiki/Category:Fireworks_PNG_files>
