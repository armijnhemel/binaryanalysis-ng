# binaryanalysis-ng
Binary Analysis Next Generation (BANG)

BANG is a framework for unpacking files (like firmware) recursively and running
checks on the unpacked files. Its intended use is to be able to find out the
provenance of the unpacked files and classify/label files, making them available
for further analysis.

## Requirements

* a recent Linux distribution (Fedora 33 or higher, or equivalent), or NixOS
* Python 3.8.x or higher
* for maintenance scripts: Python 3.9.x or higher (as some Python 3.9 specific features are used in the maintenance scripts)
* pillow (possibly named python3-pillow), a drop in replacement for PIL ( http://python-pillow.github.io/ )
* GNU binutils (for 'ar')
* squashfs-tools (for 'unsquashfs')
* cabextract
* 7z
* e2tools (for 'e2ls' and 'e2cp')
* zstd
* python-lz4 (possibly named python3-lz4)
* qemu-img (for VMDK files)
* psycopg2 (possibly named python3-psycopg2)
* python-snappy (possibly named python3-snappy)
* python-tlsh (possibly named python3-tlsh)
* tinycss2 (possibly named python3-tinycss2, not available on Fedora 26 and earlier)
* dockerfile-parse (possibly named python3-dockerfile-parse)
* openssl
* rzip
* libxml2 (for 'xmllint')
* mailcap (for mime.types)
* lzop
* OpenJDK (for 'unpack200')
* defusedxml (possibly named python3-defusedxml)
* icalendar (possibly named python3-icalendar)
* pyyaml (possibly named python3-pyyaml)
* ncompress
* util-linux (for 'fsck.cramfs')
* lz4 (for 'lz4c')
* elasticsearch (possibly named python3-elasticsearch)

or if you are fortunate enough to be using [nix](https://nixos.org/nix), run
`nix-shell` to load all the dependencies during development.

Additionally install "sasquatch"

https://github.com/devttys0/sasquatch

## Supported hardware

It is assumed that BANG is run on little endian hardware (such as x86 or x86-64).

## Verified unsupported distributions

* Fedora 32 and earlier
* Ubuntu 16.04 and lower (Python version too old)

## Docker container

```
docker image build -t bang .
docker container run --rm -it bang
```

or from the `src` directory, type

```
make dockerbuild
```



## Supported file types

The following files can be unpacked, or verified, including carving from a
larger file, unless stated otherwise.

1. WebP
2. WAV
3. ANI
4. gzip
5. LZMA
6. XZ
7. timezone files
8. tar
9. Apple Double encoded files
10. ICC (colour profile)
11. ZIP (store, deflate, bzip2, but lzma needs some more testing), also JAR and other ZIP-based formats
12. APK (same as ZIP, but possibly with extra Android signing bytes)
13. XAR (no compression, gzip, bzip2, XZ, LZMA)
14. ISO9660 (including RockRidge and zisofs)
15. lzip
16. WOFF (Web Open Font Format)
17. TrueType fonts/sfnt-housed fonts
18. OpenType fonts
19. Vim swap files (whole file only)
20. Android sparse data image
21. Android backup files
22. ICO (MS Windows icons)
23. Chrome PAK (version 4 & 5, only if offset starts at 0)
24. GNU message catalog
25. RPM (gzip, XZ, bzip2, LZMA, zstd, not: delta RPM)
26. AIFF/AIFF-C
27. terminfo (little endian, including ncurses extension, does not
    recognize some wide character versions)
28. AU (Sun/NeXT audio)
29. JFFS2 (uncompressed, zlib, LZMA from OpenWrt)
30. CPIO (various flavours, little endian)
31. Sun Raster files (standard type only)
32. Intel Hex (text files only)
33. Motorola SREC (text files only)
34. MNG
35. Android sparse image files
36. Java class file
37. Android Dex/Odex (not OAT, just carving)
38. ELF
39. SWF (uncompressed, zlib, LZMA)
40. Android resource files (table type, but possibly not all types, binary XML)
41. Java/Android MANIFEST.MF files (whole file)
42. Linux kernel configuration files (whole file)
43. Dockerfile files (whole file)
44. Python PKG-INFO files (whole file)
45. base64/32/16 (whole file)
46. SSH known hosts files (whole file)
47. FLV (Macromedia Flash Video)
48. Git index files
49. Linux Software Map files (whole file)
50. JSON (whole file)
51. D-Link ROMFS
52. Unix passwd files (whole file)
53. Unix shadow files (whole file)
54. bzip2
55. GIF (needs PIL)
56. JPEG (needs PIL)
57. Microsoft Cabinet archives (needs cabextract)
58. RZIP (requires rzip)
59. 7z (requires external tools), single frame(?)
60. Windows Compiled HTML Help (needs external tools, version 3
    only)
61. Windows Imaging file format (needs external tools, single
    image only)
62. ext2/3/4 (missing: symbolic link support)
63. zstd (needs zstd package)
64. SGI image files (needs PIL)
65. Apple Icon Image (needs PIL)
66. LZ4 (requires LZ4 Python bindings), LZ4 legacy (requires 'lz4c')
67. VMware VMDK (needs qemu-img, whole file only)
68. QEMU qcow2 (needs qemu-img, whole file only)
69. VirtualBox VDI (needs qemu-img, whole file only,
    Oracle flavour only)
70. XML (whole file)
71. Snappy (needs python-snappy)
72. various certificates (PEM, private key, etc., needs openssl)
73. lzop
74. CSS
75. PNG/APNG (needs PIL)
76. ar/deb (needs binutils)
77. squashfs (needs squashfs-tools), only regular squashfs, vendor
    specific exotic variants need sasquatch
78. BMP (needs PIL)
79. PDF (simple verification, no object streams, incremental updates
    at end of the file)
80. pack200 (needs unpack200)
81. GIMP brush (needs PIL)
82. ZIM (Wikipedia archive format)
83. MIDI
84. Android tzdata
85. Java key store (version 2 only)
86. XG3D (proprietary file format from 3D Studio Max, labeling only)
87. ACDB (audio callibration database, proprietary file format from Qualcomm, labeling only)
88. Microsoft DirectDraw Surface (structure checks and very limited sanity checking)
89. Khronos KTX files (version 1)
90. Android verified boot image
91. SQLite 3
92. Linux fstab files
93. Linux flattened device tree
94. Broadcom TRX
95. Photoshop PSD (raw bytes and RLE encoding only)
96. pkg-config files
97. minidump files
98. PPM files ('raw' PPM only)
99. PGM files ('raw' PGM only)
100. PBM files ('raw' PBM only)
101. Android bootloader for Qualcomm Snapdragon
102. Android bootloader image (also a Lttle Kernel based variant)
103. Android bootloader for Huawei devices
104. FAT16 file systems (8.3 file names)
105. iCalendar (RFC 5545) files (whole file only)
106. Coreboot images
107. Minix V1 file system (Linux variant)
108. Unix compress (needs 'uncompress'), only if end
     of the file is compress'd data
109. Unix group files (whole file)
110. TRANS.TBL files
111. romfs
112. cramfs (version 2 only)
113. nb0 Android updates
114. Quake PAK files
115. Doom WAD files (IWAD only)
116. Ambarella firmware files
117. Ambarella romfs (used in Ambarella firmware files)
118. bFLT
119. Samba password files
120. UBI (not UBIFS!), fastmap not supported
121. GRUB2 font files
122. BitTorrent files (subset)
123. pcapng (carving, structural checks, little endian only)
124. pcap (carving, structural checks)
125. serialized Java (block data only, carving, structural checks)
126. mapsforge map files (very basic structural checks)
127. Parrot PLF files
128. Windows INI files (text only)
129. Subversion hash files (wcprops, all-wcprops, etc.)
130. PFS file system
131. YAFFS2 (including inband tags)
132. Qualcomm QCDT files
133. Chrome extensions (.crx)
134. Windows shell link file (.lnk)
135. PCF fonts (that actually follow the specification)
136. DS_Store
137. Qualcomm Snapdragon MSM bootloader files
138. Mozilla ARchive (.mar)
139. OpenFst (subset, identification only)
140. SELinux file context
141. Ogg


## Invocation

    $ python3 bang-scanner -c bang.config -f /path/to/binary

Depending on the `baseunpackdirectory` defined in your `bang.config`, the results
will be found in `~/tmp/report.txt`, for instance.  You may also enable an additional
JSON output, PostgrSQL or ElasticSearch server to write results to.

## License

GNU Affero General Public License, version 3 (AGPL-3.0)

The code for unpacking D-Link ROMFS file systems was heavily inspired by
binwalk and modified (and improved) for use with BANG.

The original license for the binwalk code:

    The MIT License (MIT)

    Copyright (c) 2010-2015 Craig Heffner

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The code for verifying and labeling Android Verified Boot images was heavily
inspired by code from Android (avbtool) found at:

https://android.googlesource.com/platform/external/avb/+/master/avbtool

The original license for avbtool:

    Copyright 2016, The Android Open Source Project

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy,
    modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

## Developing

The recommended coding style is described in PEP 8:

https://www.python.org/dev/peps/pep-0008/

It is recommended to run PEP 8 verification tools, for example
python3-flake8 (on Fedora).

Another tool that is highly recommended is pylint.

# Acknowledgement

This project has received funding from the European Union’s Horizon 2020
research and innovation programme within the framework of the NGI-POINTER
Project funded under grant agreement No. 871528.
