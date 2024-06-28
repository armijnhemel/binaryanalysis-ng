# binaryanalysis-ng
Binary Analysis Next Generation (BANG)

BANG is a framework for processing binary files (like firmware). It consists of
an unpacker that recursively unpacks and classifies/labels files and separate
analysis programs that work on the results of the unpacker.

Some intended uses:

* provenance detection ("what is inside this file")
* security scans ("are there any known security risks associated with this file")

## Requirements

The recommended way is to use [Nix](https://nixos.org/nix), run
`nix-shell` to load all the dependencies for the unpacker,
`nix-shell maintenance.nix` for the maintenance scripts,
`nix-shell analysis.nix` for the analysis scripts and `nix-shell scraper.nix`
for the firmware scraper.

`nix` will make sure that everything is downloaded and installed to run BANG.

### Other distributions without Nix

Note: this list is vastly incomplete. It is highly recommended to use Nix.

* a recent Linux distribution (Fedora 36 or higher, or equivalent)
* Python 3.10.x or higher
* pillow (possibly named python3-pillow), a drop in replacement for PIL ( <http://python-pillow.github.io/> )
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
* dockerfile-parse (possibly named python3-dockerfile-parse)
* openssl
* rzip
* lzop
* defusedxml (possibly named python3-defusedxml)
* icalendar (possibly named python3-icalendar)
* pyyaml (possibly named python3-pyyaml)
* ncompress
* util-linux (for 'fsck.cramfs')
* lz4 (for 'lz4c')
* bzip3

and many others (see `shell.nix`, `maintenance.nix` and `analysis.nix` for a
full list).

You will also need to install the Kaitai Struct compiler. This is described in
the file `doc/kaitai-struct.md`.

Additionally install `sasquatch`:

<https://github.com/devttys0/sasquatch>

## Supported hardware

It is assumed that BANG is run on little endian hardware (such as x86 or x86-64).

## Verified unsupported distributions

* Fedora 35 and earlier
* Ubuntu 16.04 and lower (Python version too old)

This doesn't mean that newer versions of Ubuntu are supported, they just
haven't been tested.

## Docker container (recently untested, assume broken)

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
11. ZIP (store, deflate, bzip2, but lzma needs some more testing), also JAR, APK (possible with extra Android signing bytes) and other ZIP-based formats, dangling entries without a valid central directory
12. U-Boot image
13. XAR (no compression, gzip, bzip2, XZ, LZMA)
14. ISO9660 (including RockRidge and zisofs)
15. lzip
16. WOFF (Web Open Font Format)
17. TrueType fonts/sfnt-housed fonts
18. OpenType fonts
19. Vim swap files (whole file only)
20. Android sparse data image (regular and Brotli compression, no bsdiff/imgdiff)
21. Android backup files
22. ICO (MS Windows icons)
23. Chrome PAK (version 4 & 5, only if offset starts at 0)
24. GNU message catalog
25. RPM (gzip, XZ, bzip2, LZMA, zstd, not: delta RPM)
26. AIFF/AIFF-C
27. terminfo (little endian, regular and extended storage format, not
    extended number format)
28. AU (Sun/NeXT audio)
29. JFFS2 (uncompressed, zlib, rtime, lzo, LZMA from OpenWrt)
30. CPIO (various flavours, little endian)
31. Sun Raster files (standard type only)
32. Intel Hex (text files only)
33. Motorola SREC (text files only)
34. Quicktime
35. Android sparse image files
36. Java class file
37. Android Dex/Odex (not OAT, just carving)
38. ELF
39. SWF (uncompressed, zlib, LZMA)
40. Android resource files (table type, but possibly not all types, binary XML)
41. base64/32/16 (whole file)
42. FLV (Macromedia Flash Video)
43. Git index files
44. JSON (whole file)
45. D-Link ROMFS
46. bzip2
47. GIF (needs PIL)
48. JPEG (needs PIL)
49. Microsoft Cabinet archives (needs cabextract)
50. RZIP (requires rzip)
51. 7z (requires external tools), single frame(?)
52. Windows Compiled HTML Help (needs external tools, version 3
    only)
53. Windows Imaging file format (needs external tools, single
    image only)
54. ext2/3/4 (missing: symbolic link support)
55. zstd (needs zstd package)
56. SGI image files (needs PIL)
57. Apple Icon Image (needs PIL)
58. LZ4 (requires LZ4 Python bindings), LZ4 legacy (requires 'lz4c')
59. VMware VMDK (needs qemu-img, whole file only)
60. QEMU qcow2 (needs qemu-img, whole file only)
61. VirtualBox VDI (needs qemu-img, whole file only,
    Oracle flavour only)
62. XML (whole file)
63. Snappy framing2 format (needs python-snappy)
64. various certificates (PEM, private key, etc., needs openssl)
65. lzop
66. PNG/APNG (needs PIL)
67. ar/deb (needs binutils)
68. squashfs (using squashfs-tools), vendor specific exotic variants
    (using sasquatch)
69. BMP (needs PIL)
70. PDF (simple verification, no object streams, incremental updates
    at end of the file)
71. GIMP brush (needs PIL)
72. ZIM (Wikipedia archive format)
73. MIDI
74. Android tzdata
75. Java key store (version 2 only)
76. XG3D (proprietary file format from 3D Studio Max, labeling only)
77. ACDB (audio callibration database, proprietary file format from Qualcomm, labeling only)
78. Microsoft DirectDraw Surface (structure checks and very limited sanity checking)
79. Khronos KTX files (version 1)
80. Android verified boot image
81. SQLite 3
82. Linux flattened device tree
83. Broadcom TRX
84. Photoshop PSD (raw bytes and RLE encoding only)
85. minidump files
86. PPM files ('raw' PPM only)
87. PGM files ('raw' PGM only)
88. PBM files ('raw' PBM only)
89. Android bootloader image for Qualcomm Snapdragon (MSM)
90. Android bootloader image (also a Little Kernel based variant)
91. Android bootloader image for Huawei devices
92. FAT16 file systems (8.3 file names)
93. Coreboot images
94. Minix V1 file system (Linux variant)
95. Unix compress (needs 'uncompress'), only if end
     of the file is compress'd data
96. romfs
97. cramfs (version 2 only)
98. nb0 Android updates
99. Quake PAK files
100. Doom WAD files (IWAD only)
101. Ambarella firmware files
102. Ambarella romfs (used in Ambarella firmware files)
103. bFLT
104. UBI, fastmap not supported
105. GRUB2 font files
106. BitTorrent files (subset)
107. pcapng (carving, structural checks, little endian only)
108. pcap (carving, structural checks)
109. serialized Java (block data only, carving, structural checks)
110. mapsforge map files (very basic structural checks)
111. Parrot PLF files
112. PFS file system
113. YAFFS2 (including inband tags)
114. Qualcomm QCDT files
115. Chrome extensions (.crx)
116. Windows shell link file (.lnk)
117. PCF fonts (that actually follow the specification, little endian only)
118. DS\_Store
119. libminikin hyb text layout format
120. Mozilla ARchive (.mar)
121. OpenFst (subset, identification only)
122. SELinux file context
123. Ogg
124. Allwinner images
125. DFU (Device Firmware Upgrade)
126. Key Character Map binary files
127. USB Flashing Format (UF2)
128. Android VDEX (identification only)
129. SEAMA firmware files
130. LLVM IR wrapper format (identification only)
131. OpenWrt LXL firmware header
132. Mediatek BootROM (header only)
133. Rockchip RKFW and RKAF
134. systemd journal files
135. Rockchip rkboot
136. Python pickle
137. glibc utmp/wtmp
138. Android vendor boot
139. Android FBPK
140. Samsung Tzar
141. Qualcomm aboot (version 3 only, no unified boot)
142. Rockchip resource files
143. Socionext Milbeaut firmware files
144. zchunk
145. ubifs
146. Performance Co-Pilot metadata files
147. data URI (PNG, GIF, JPEG, WEBP, certain fonts, SVG, PDF, JSON and octet-stream objects)
148. DHTB signed files
149. Android AAPT2 container format
150. Android update image (version 2 only, full OTA image only)
151. Qt resource files (`.rcc`)
152. glibc locale archive file detection
153. Sunplus BRN firmware
154. xo65 object files
155. DOS MZ, plus COFF for MS-DOS, DJGPP go32 DOS extender
156. WinHelp (older formats only)
157. PEF (Preferred Executable Format)
158. Nano app header (Android)
159. WebAssembly binaries
160. Android super images
161. Qualcomm QTI Chromatix (structural checks only)
162. Mediatek images (including logo.bin)
163. Android DTO
164. Portable Image Format
165. ResPack.cfg (seen in CPB firmware format)
166. LOD (RDA/Coolsand phone firmware format)
167. MediaTek secure ROM(?) info
168. lrzip
169. SerpentOS .stone package file
170. systemd hwdb.bin
171. Qt Translation files
172. Reolink firmware
173. Xiaomi firmware
174. HP BDL firmware
175. Netgear .chk firmware files
176. Instar BNEG firmware files
177. Huawei HWNP firmware files
178. Reolink 'logo' file
179. FLS firmware files (IP cameras)
180. TP-Link TX6610v4 firmware
181. Granite Devices firmware v300
182. erofs
183. bzip3
184. PX4 autopilot firmware files
185. SSH known hosts files (whole file)
186. Unix passwd files (whole file)
187. Unix group files (whole file)
188. Unix shadow files (whole file)
189. Samba password files
190. Linux fstab files
191. Java/Android MANIFEST.MF files (whole file)
192. Linux kernel configuration files (whole file)
193. pkg-config files
194. iCalendar (RFC 5545) files (whole file only)
195. Windows INI files (text only)
196. Linux Software Map files
197. exFAT ("no FAT chains" only)
198. Subversion hash files (wcprops, all-wcprops, etc.)
199. Python PKG-INFO files (whole file)
200. Dockerfile files (whole file)
201. TRANS.TBL files
202. BTF and BTF.ext sections (BPF related)
203. NibArchive
204. EDID
205. ld.so.conf files (subset, no include statements)
206. old TP-Link firmware files
207. certain VxWorks memfs file systems
208. Realtek bootloader (subset of files)
209. Linux kernel x86 images
210. TP-Link minifs
211. ANJVision IP camera firmware files
212. Linux `securetty` files (whole file)

## Getting started

This section assumes that you are using Nix to install all dependencies.

1. `git clone` this repository
2. run `nix-shell` to install all the dependencies and start a complete environment
3. `cd src`
4. run `make` to build all the Kaitai Struct parsers. Please note: this might take
   a while!

To unpack a file run (from the `src` directory):

    $ python3 -m bang.cli scan -u /path/to/unpack/directory /path/to/binary

This will output a directory with inside a number of files and directories.
The output directory can serve as input to the analysis scripts (and some
knowledgebase scripts).

To process each file in a directory run (from the `src` directory):

    $ python3 -m bang.cli scan-directory -u /path/to/unpack/directory /path/to/directory/with/binaries

This will create a directory with search results for each file that is scanned,
with the same name as the file that is scanned, using the same structure as if
the file was scanned in regular mode, not directory mode.

## License

GNU Affero General Public License, version 3 (AGPL-3.0)

The code for verifying and labeling Android Verified Boot images was heavily
inspired by code from Android (`avbtool`) found at:

<https://android.googlesource.com/platform/external/avb/+/refs/heads/master/avbtool.py>

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


The code for rtime decompression was copied from:

<https://github.com/sviehb/jefferson/blob/master/src/jefferson/rtime.py>

The original license for jefferson:

    The MIT License (MIT)

    Copyright (c) 2015 Stefan Viehböck

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

## Developing

The recommended coding style is described in PEP 8:

<https://www.python.org/dev/peps/pep-0008/>

It is recommended to run PEP 8 verification tools, for example
python3-flake8 (on Fedora).

Another tool that is highly recommended is `pylint`.

# Acknowledgement

This project has received funding from the European Union’s Horizon 2020
research and innovation programme within the framework of the NGI-POINTER
Project funded under grant agreement No. 871528.
