# List of labels used in BANG

In BANG labels are used to pass information about files around. A single
file can have multiple labels, such as a quite generic label about the type
of file ('graphics', 'audio', etc.), or very specific ('animated' for an
animated graphics file).

Below is a list of labels that are used throughout BANG. They have been
ordered per category to make it easier to search. There is some overlap
between categories and some labels will appear multiple times, as they belong
to several categories.

Generic labels:

* text :: file is an ASCII file (printable characters)
* binary :: all files that are not 'text'
* corrupt :: file is corrupt
* encrypted :: file is encrypted
* partially unpacked :: file has been partially unpacked
* unpacked :: this is a label for internal use to flag that a file has already been unpacked, so it doesn't need further processing

Generic categories:

* android :: file is specific to Android
* archive :: file is an archive file
* audio :: file is an audio file
* compressed :: file is a compressed file
* debian :: file is specific to Debian (or derivates)
* filesystem :: file is a file system
* font :: file is a font
* graphics :: file is a graphics file
* resource :: file is a resource file (data, etc.)
* riff :: file is a RIFF container
* video :: file is a video file

Android specific

* android backup :: file is an Android backup file
* androidsparse :: file is an Android sparse file
* androidsparsedata :: file is an Android sparse data file
* apk :: file is an Android APK file
* dex :: file is an Android Dex file
* odex :: file is an Android Optimized Dex file

Archive specific

* 7z :: file is a 7z compressed archive
* ar :: file is a Unix ar archive
* cab :: file is a Microsoft Cabinet archive
* cpio :: file is a CPIO archive
* deb :: file is a Debian archive file
* mswim :: file is a Microsoft Windows Imaging file
* tar :: file is a tar archive
* xar :: file is a XAR archive

Audio specific

* aiff :: file is an AIFF file
* au :: file is a Sun AU file
* wav :: file is a WAV file

Compressed specific

* 7z :: file is a 7z compressed archive
* apk :: file is an Android APK file
* bzip2 :: file is bzip2 compressed
* chm :: file is a Microsoft CHM file
* gzip :: file is gzip compressed
* lz4 :: file is LZ4 compressed
* lzip :: file is lzip compressed
* lzma :: file is LZMA compressed
* mswim :: file is a Microsoft Windows Imaging file
* python egg :: file is a Python egg file
* rzip :: file is rzip compressed
* snappy :: file is snappy compressed
* xz :: file is XZ compressed
* zip :: file is ZIP compressed
* zstd :: file is zstd compressed

Debian specific

* deb :: file is a Debian archive file

File system

* ext2 :: file is an ext2/ext3/ext4 file system
* iso9660 :: file is an ISO9660 file system
* jffs2 :: file is a JFFS2 file system
* qcow2 :: file is a QEMU qcow2 image
* squashfs :: file is a squashfs file system
* vdi :: file is a VirtualBox VDI image
* vmdk :: file is a VMWware VMDK image

Fonts

* fontcollection :: file is a font collection
* otf :: file is an OpenType font
* ttf :: file is a TrueType font
* woff :: file is a WOFF font

Graphics specific:

* ani :: file is an ANI graphics file
* animated :: file is an animated graphics file
* apng :: file is an APNG file
* apple icon :: file is an Apple icon file
* bmp :: file is a BMP file
* gif :: file is a GIF file
* ico :: file is an ICO file
* jpeg :: file is a JPEG file
* mng :: file is a MNG file
* png :: file is a PNG file
* raster :: file is a raster image file
* sgi :: file is an SGI graphics file
* sun raster :: file is a Sun raster image file
* webp :: file is a WebP graphics file

Resource specific

* appledouble :: file is an AppleDouble encoded file
* apple icon :: file is an Apple icon file
* chm :: file is a Microsoft CHM file
* fontcollection :: file is a font collection
* git index :: file is a Git index file
* gnu message catalog :: file is a GNU message catalog file
* icc :: file is an ICC colour profile file
* ico :: file is an ICO file
* linux software map :: file is a Linux Software Map file
* otf :: file is an OpenType font
* pak :: file is a Chrome PAK file
* terminfo :: file is a terminfo file
* timezone :: file is a Unix timezone file
* ttf :: file is a TrueType font
* woff :: file is a WOFF font

Text

* base16 :: file is a BASE16 file
* base32 :: file is a BASE32 file
* base64 :: file is a BASE64 file
* certificate :: file is a certificate
* css :: file is a CSS file
* ihex :: file is an Intel Hex file
* javamanifest :: file is a Java manifest file
* kernel configuration :: file is a Linux kernel configuration file
* private key :: file contains a private key
* srec :: file is a Motorola SREC file
* ssh known hosts :: file is a SSH known hosts file
* trusted certificate :: file is a certificate

Video

* flv :: file is a FLV file
* swf :: file is a SWF file

Misc

* dockerfile :: file is a Dockerfile
* drpm :: file is a delta RPM file
* elf :: file is an ELF file
* java class :: file is a Java class file
* python pkg-info :: file is a Python PKG-INFO file
* rpm :: file is a RPM file
* source rpm :: file is a source RPM file
* srpm :: file is a source RPM file
* u-boot :: file is a legacy U-Boot file
* vimswap :: file is a Vim swap file
* xml :: file is an XML file
