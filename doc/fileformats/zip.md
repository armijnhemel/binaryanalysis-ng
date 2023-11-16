# ZIP file format

This document describes ZIP files and all of the different variants that have
been encountered while working on BANG.  While there are some references to
BANG this document is by no means exclusive to BANG and more of a generic
documentation of quirks encountered in real life ZIP files and how some have
perverted the ZIP file format.

Some of the information in this document has already been published in a blog
post which you can find at:

<http://web.archive.org/web/20180718185811/http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html>

The official ZIP file specification (latest is 6.3.10) can be found at:

<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>

In the rest of this document there will be references to sections in the
official specification.

## ZIP file overview

A ZIP file typically consists of a series of entries, optionally some metadata
related to archives and encryption, followed by a structure called the "central
directory" (section 4.3.6). The central directory essentially serves as a lookup
table to provide quick access to the files inside the ZIP archive. It is then
followed by (optional) ZIP64 records and finally a variable length record called
"end of central directory" that contains the offset from the start of the ZIP data
to the central directory.

In most cases unpacking ZIP data comes down to:

1. open the file
2. jump to the end of the file
3. search the data backwards for the beginning of the "end of central directory
   record" (section 4.3.16) and process it to find the correct offset for the
   central directory which contains the offsets, sizes, etc. for the individual
   entries.
4. jump to the start of the central directory relative to the start of the ZIP
   file (section 4.3.12)
5. parse the entries in the central directory, determine types and offsets of
   each individual entry and extract the entries

This method works very well if the central directory and the records following
it (optional ZIP64 data, end of central directory) can be found at the end of the
file and is correct. For most ZIP files this is the case.

If this is not the case, for example when a ZIP file is part of a larger file
(such as a blob like a firmware dump), then it becomes a lot harder to unpack
data, or it could be that the other data than expected is unpacked. Two
examples can help illustrate this.

### Example 1: ZIP file with extra data after the central directory

If extra data is appended to a file, then the method as described above does
not always work with most popular ZIP tools or unpacking libraries, as
illustrated by the following example.

First create a ZIP file and test that it can be unpacked:

```
$ zip -r test.zip /bin/ls
  adding: bin/ls (deflated 55%)
$ file test.zip
test.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
$ unzip -l test.zip
Archive:  test.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   142104  08-08-2022 16:57   bin/ls
---------                     -------
   142104                     1 file
```

Then append data to the ZIP file, for example an ELF file, and test to see if
the data can be unpacked:

```
$ cat /bin/ls >> test.zip
$ file test.zip
test.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
$ unzip -l test.zip
Archive:  test.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
unzip:  cannot find zipfile directory in one of test.zip or
        test.zip.zip, and cannot find test.zip.ZIP, period.
```

The amount of data that can be appended before a program or library no longer
can recognize a file as a valid ZIP file actually differs per program or
library.

The "end of central directory" record is a variable length record, because there
can be a file comment. Section 4.3.16 specifies the length as:

```
.ZIP file comment length        2 bytes
.ZIP file comment       (variable size)
```

The length of the ZIP file comment is stored in 2 bytes, so the file comment
itself has a maximum of 65536 bytes.

The `zipfile` module in Python 3.10 uses exactly this length and cannot unpack
if there is more data appended to the file.

The `unzip` programma used on Fedora (UnZip 6.00) uses a different limit,
namely `67633` bytes, which can be verified as follows. When adding `67633`
bytes `unzip` still works:

```
$ dd if=/dev/random of=bla bs=67633 count=1
1+0 records in
1+0 records out
67633 bytes (68 kB, 66 KiB) copied, 0.00107098 s, 63.2 MB/s
$ cat /tmp/test.zip /tmp/bla > test2.zip
$ unzip -l test2.zip
Archive:  test2.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   142104  08-08-2022 16:57   bin/ls
---------                     -------
   142104                     1 file
```

If one extra byte is added then `unzip` can no longer find the end of central
directory record and not unpack the archive:

```
$ dd if=/dev/random of=bla bs=67634 count=1
1+0 records in
1+0 records out
67634 bytes (68 kB, 66 KiB) copied, 0.00109499 s, 61.8 MB/s
$ cat /tmp/test.zip /tmp/bla > test2.zip
$ unzip -l test2.zip
Archive:  test2.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
unzip:  cannot find zipfile directory in one of test2.zip or
        test2.zip.zip, and cannot find test2.zip.ZIP, period.
```

`p7zip` does not seem to suffer from having a limit at all, because even after
adding 11 MiB of random garbage it still manages to find the file, although it
warns about trailing data:

```
$ dd if=/dev/random of=/tmp/bla bs=11167633 count=1
1+0 records in
1+0 records out
11167633 bytes (11 MB, 11 MiB) copied, 0.0645893 s, 173 MB/s
$ cat /tmp/test.zip /tmp/bla > test2.zip
$ 7z l test2.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 11231853 bytes (11 MiB)

Listing archive: test2.zip

--
Path = test2.zip
Type = zip
WARNINGS:
There are data after the end of archive
Physical Size = 64220
Tail Size = 11167633

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-01-04 14:04:07 .....       142088        64058  bin/ls
------------------- ----- ------------ ------------  ------------------------
2023-01-04 14:04:07             142088        64058  1 files

Warnings: 1
```

It is possible that other tools use different limits.

If there is more data than what the tools or libraries allowed and data still
needs to be unpacked from the ZIP file, then it becomes necessary to find out
where the ZIP file starts and ends, and then unpack all the data.

### Example 2: Two concatenated ZIP files

Imagine that there are two ZIP files A and B. When these are concatenated (A,
then B) and then unpacked using the standard method the central directory of
B will be at the end, so only the entries of file B will be found. To unpack
entries from A you need to find out where the central directory of A resides.
This can only be done by parsing from the beginning of the file.


```
$ zip -r test2.zip /bin/vim
  adding: bin/vim (deflated 48%)
$ cat /tmp/test.zip /tmp/test2.zip > /tmp/test3.zip
```

`unzip` says:

```
$ unzip -l /tmp/test3.zip
Archive:  /tmp/test3.zip
warning [/tmp/test3.zip]:  64220 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  Length      Date    Time    Name
---------  ---------- -----   ----
  4190040  04-25-2023 12:54   bin/vim
---------                     -------
  4190040                     1 file
```

and it unpacks the second archive, but warns about extra data at the beginning
(namely the first ZIP file).

`p7zip` on the other hand only finds the first ZIP file and warns about extra
data at the end (namely the second ZIP file):

```
$ 7z l /tmp/test3.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2223938 bytes (2172 KiB)

Listing archive: /tmp/test3.zip

--
Path = /tmp/test3.zip
Type = zip
WARNINGS:
There are data after the end of archive
Physical Size = 64220
Tail Size = 2159718

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-01-04 14:04:07 .....       142088        64058  bin/ls
------------------- ----- ------------ ------------  ------------------------
2023-01-04 14:04:07             142088        64058  1 files

Warnings: 1
```

# ZIP file unpacking in BANG

In BANG it is assumed that ZIP files are always followed by extra data and
need to be carved, so parsing starts from the beginning of the file, instead of
using the central directory of the ZIP file to locate and access the files.

ZIP file unpacking in BANG works as follows (simplified):

1. open the file at a specific offset (namely where a local file header was
   found)
2. go to the start of the first local file header (section 4.3.7)
3. read and parse the data in a local file header
4. skip the compressed data
5. process all entries and any optional extra data such as APK signing blocks,
   until a central directory is found (section 4.3.12)
6. process the central directory and verify if the contents in the central
   directory correspond to the entries found in step 5.
7. verify if there is an end of central directory (section 4.3.16)
8. carve the ZIP file (if necessary) and process using standard tools
   (Python's `zipfile` module)

This (simplified) workflow works well, but as it turns out there are a few
situations that make this tricky.

# Parsing a ZIP file from the beginning of the file

In this section the whole structure of a ZIP file is explained and exceptions
that have been encountered are highlighted.

Every ZIP file starts with a local header.

## Local file header

The static part of every local file header is 30 bytes and structured as
follows (section 4.3.7):

```
local file header signature     4 bytes  (0x04034b50)
version needed to extract       2 bytes
general purpose bit flag        2 bytes
compression method              2 bytes
last mod file time              2 bytes
last mod file date              2 bytes
crc-32                          4 bytes
compressed size                 4 bytes
uncompressed size               4 bytes
file name length                2 bytes
extra field length              2 bytes
```

Schematically it looks like this:

```
+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
|  P   |   K  | 0x03 | 0x04 | version     | flag        | compression | mod time    | mode date   | crc32       |
+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
| crc32 (ctd) |     compressed size       |     uncompressed size     | name length | extra length|
+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
```

The static part is followed by a variable part:

```
file name (variable size)
extra field (variable size)
```

### Local file header signature

The first exception is that there are certain vendors that have changed the
local file header signature. One example is the Chinese IP camera vendor Dahua.
The first local file header is changed from `PK\x03\x04` to `DH\x03\x04`. By
changing the first local file header signature back to `PK\x03\x04` allows
the ZIP file to be unpacked.

### Version needed to extract

The ZIP file was not complete upon release: new features have been introduced
in later versions of the ZIP format. Older versions of the program will not be
able to process files with these new featuers, so the "version needed to
extract" field can be used to flag which version is needed. This flag is
repeated in various other headers ("central directory header", "zip64 end of
central directory") as well.

As an example, for ZIP64 files the minimum feature version that the extraction
program needs to implement is `4.5`. If a ZIP64 file is written, then the
program writing the ZIP file needs to set the version needed to extract to
`4.5` or higher. The list of minimum feature versions that have been defined
can be found in section 4.4.3.

Storing a file in a ZIP archive with the `store` method (which only stores it
without any compression) requires version `1.0` to be supported:

In the local file header the version number is not split in "major/minor", but
stored in a different way. To get back to the version in section 4.4.3 the
value has to be divided by `10`.  For example, "version 4.6" will be stored as
`0x2e` (`46`) in the file header.

```
$ zip -r test.zip -Z store /bin/ls
  adding: bin/ls (stored 0%)
$ file test.zip
test.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

Storing the contents with BZip2 compression (minimum version `4.6`) will record
another minimum version:

```
$ zip -r test2.zip -Z bzip2 /bin/ls
  adding: bin/ls (bzipped 55%)
$ file test2.zip
test2.zip: Zip archive data, at least v4.6 to extract, compression method=bzip2
```

The minimum version needed to extract is recorded *per file* and inside a ZIP
file these can be different per files. A small example to illustrate:

```
$ mkdir test
$ cp /bin/ls test
$ zip -r test.zip test
updating: test/ (stored 0%)
updating: test/ls (deflated 55%)
$ file test.zip
test.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

This file is storing a directory (minimum version `1.0`) but compressing a file
with the `deflate` algorithm (minimum version `2.0`). The `file` command only
looks at the first few bytes of the file, but when using `zipinfo -v` (as well
as when inspecting the file itself) it can clearly be seen that the minimum
version for the file compressed with `deflate` is in fact `2.0` (output edited
for clarity):

```
Central directory entry #2:
---------------------------

  test/ls

  offset of local header from start of archive:   63
                                                  (000000000000003Fh) bytes
  file system or operating system of origin:      Unix
  version of encoding software:                   3.0
  minimum file system compatibility required:     MS-DOS, OS/2 or NT FAT
  minimum software version required to extract:   2.0
```

When parsing a file it could be that invalid versions are encountered. The
latest published ZIP version is `6.3` which would be stored as `0x3f` in the
local file header.

There are a few files where the minimum version has a non-existent version
number in the local file header, but not in the central directory. As an
example in one file the value `0x314` was observed.

As long as the value of the corresponding field in the central directory is
valid it is advised to silently ignore the invalid versions (this is what BANG
does), as the unpacking tools and libraries primarily rely on the data in the
central directory, not in the local file header. As long as the data in the
central directory is valid the file can be unpacked.

### General purpose bit flag

The general purpose bit flag (section 4.4.4) has a few important bits, namely
"encryption" (bit 0) and "data descriptor" (bit 3). This flag is repeated in
the corresponding central directory header for the file (and is expected to be
the same).

#### Encryption

Entries in ZIP files can be encrypted with a variety of methods. The standard
password encryption is weak (and prone to a known plaintext attack). If an entry
is encryted then the "encryption" bit in the general purpose bit flag is set.
In case an encrypted entry is found and there is no password available then it
still possible to do structural checks (extract file name, CRC32, and so on)
and verify if the data is sound.

Other encryption methods are stronger. Depending on the encryption method the
encryption bit flag might or might not be set. For example: for AE-x it will
be set (APPENDIX E), while for other encryption methods it might not. The flag
should not be used as the sole indicator of encrypption.

#### Data descriptor

If bit 3 of the general purpose bit flag is set, then it means that certain
fields in the local file header have not been filled in and can be found in a
so called "data descriptor" (section 4.3.9) that directly follows the data:

```
If this bit is set, the fields crc-32, compressed size and uncompressed size
are set to zero in the local header.  The correct values are put in the data
descriptor immediately following the compressed data.
```

This means that first the data of the entry should be read (or skipped), before
the size of the entry can be correctly determined (from the data descriptor).
This sounds like an impossible task, but there are a few markers in the file
that can help.

First of all, although the data descriptor does not have a standard signature
(and the data descriptor could consist of only the fields from section 4.3.9
and nothing more) there often is a signature present (section 4.3.9.3).

If there is no signature present, then the some other markers have to be used.
If the entry is followed by another entry, then that next entry will start with
a local file header signature. If it is the last entry it will be followed by
either an archive header or central directory header or, in case of Android APK
files, an APK signing block.

By searching for:

* data descriptor signature (`PK\x07\x08`)
* a local file header (`PK\x03\x04`)
* another known header (central directory, archive headers)
* APK signing block

and then processing the data descriptor it should be possible to correctly
determine the size. Verifications of the size in the data descriptor to see
if it is correct should be done to prevent bogus data. For example, it could
be that another ZIP file could be stored in the entry, so when encountering
for example a local file header it might not be of the next entry but that
of an embedded ZIP file.

The data descriptor itself is defined as follows (section 4.3.9):

```
crc-32                          4 bytes
compressed size                 4 bytes
uncompressed size               4 bytes
```

but section 4.3.9.1 says that if ZIP64 is used the size fields are 8 bytes
instead:

```
For ZIP64(tm) format archives, the compressed and uncompressed sizes are
8 bytes each.
```

meaning that it would look like this:

```
crc-32                          4 bytes
compressed size                 8 bytes
uncompressed size               8 bytes
```

meaning that some extra care should be taken in case of it is a 64 bit ZIP
file. As there are usually hints that it is a 64 bits file (example: the
minimum needed version) it should be clear which version should be used.

Potentially there are four variants of the data descriptor: 32 bit and 64 bit,
with and without signature. The 64 bit without signature variant has not been
encountered so far.

Good test files to find a data descriptor (with signature) are many Android APK
files from (fairly) recent devices.

### Compression method

Files can be compressed using a variety of methods (section 4.4.5). While in
practice most files are compressed using `deflate` (which is well supported)
there are files that are compressed with different compression algorithms and
which cannot always be unpacked with the standard tools BANG uses.

The `zipfile` module in Python only supports `stored`, `deflate`, `bzip2` and
`lzma` compression. One file that was encountered in the wild was compressed
using the very ancient `shrunk` compression method, which cannot be unpacked.
BANG will not process these files.

### Last modification time and last modification date

The date and time fields are in MS-DOS format (section 4.4.6) but are best
ignored. They should not be parsed or validated as sometimes there are invalid
dates (for example: `1980-00-00`):

<https://github.com/kaitai-io/kaitai_struct_formats/issues/562>

In certain cases (like when using some forms of encryption) the date could also
be zeroed out completely:

```
If encrypting the central directory and general purpose bit flag 13 is set
indicating masking, the value stored in the Local Header will be zero.
```

### CRC32

The CRC32 field is a 4 byte field that is replicated in the central directory.
The values of the CRC32 in the local file header and corresponding central
directory entry should match. There are exceptions: in some cases the value
of the CRC32 in the local header will be `0`:

```
If bit 3 of the general purpose flag is set, this
field is set to zero in the local header and the correct
value is put in the data descriptor and in the central
directory.
```

This means that when using the CRC32 in the local file header for sanity
checking (for example, by comparing it to the value in the corresponding
central directory header) this should be taken into consideration and the
CRC32 from the data descriptor should be used, if not set in the local file
header as well.

In certain encrypted files the CRC32 field is also zeroed:

```
When encrypting the central directory, if the
local header is not in ZIP64 format and general purpose
bit flag 13 is set indicating masking, the value stored
in the Local Header will be zero.
```

### Compressed size and uncompressed size

The compressed size and uncompressed size (size of the original file) are
four byte fields. There a few situations where these fields do not contain
the actual length.

When a flag in the general purpose flag is set the real size will follow
the data in a data descriptor:

```
If bit 3 of the general purpose bit flag is set,
these fields are set to zero in the local header and the
correct values are put in the data descriptor and
in the central directory.
```

When ZIP64 is used it will be in an "extra field" in the local file header:

```
If an archive is in ZIP64 format
and the value in this field is 0xFFFFFFFF, the size will be
in the corresponding 8 byte ZIP64 extended information
extra field.
```

Of course, the local file header should actually contain an "extra field".

### File name length, extra field length, comment field length

Section 4.4.10 - 4.4.12 document the file name length, extra field length and
notes the following *optional* restriction:

```
The length of the file name, extra field, and comment
fields respectively.  The combined length of any
directory record and these three fields SHOULD NOT
generally exceed 65,535 bytes.  If input came from standard
input, the file name length is set to zero.
```

In practice this is not a check that should be implemented. In Python it is
very easy to create a file where these files are each 65,535 bytes in length:

```
>>> import zipfile
>>> z = zipfile.ZipInfo(40000*'a')
>>> z.comment = 65535*b'b'
>>> contents = 40000*b'c'
>>> bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
>>> bla.writestr(z, contents)
>>> bla.close()
```

This will create a ZIP file with a very long file name and a very long comment
that together exceed 65,535 bytes. Most of the ZIP tools will be able to
process a file like this just fine although it is very likely that the file
system will impose limits on the length of the file name.

### Extra fields

## APK signing blocks

Android APK files are essentially ZIP files. To increase security Google added
signatures, or so called "APK signing blocks". Three versions have been
published so far. Since there is no standard header in the ZIP file format for
this information Google decided to add it after the last data descriptor and
before the central directory. Even though this is not allowed according to the
specifications it will work because every unpacking program (except, of course,
BANG) will simply read the central directory to get the offsets for the
individual file entries. As long as the offsets in the central directory are
correct it doesn't really matter how much extra data is in the file and where
this data is in the ZIP file.

In some files the APK signing block is aligned to 4096 bytes:

<https://android.googlesource.com/platform/tools/apksig/+/24aeb9bff8b6479397960eadac9283cc8a509f0b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#851>

If this is the case, then there will be a padding block identifier:

<https://android.googlesource.com/platform/tools/apksig/+/24aeb9bff8b6479397960eadac9283cc8a509f0b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#98>

but this identifier doesn't appear at the start of the signing block, but at
the end (which makes sense when reading from the end of the file).

## ZIP64

The size field in the local file header cannot store a number larger than
4,294,967,295 bytes (4 bytes, maximum `0xffffffff`). If a file is equal to or
larger than this number the actual size is stored in the "extra field" in the
local file header (section 4.3.7). Storing files with file sizes equal to or
larger than this limit is referred to as ZIP64. The specification of ZIP64
(section 4.5.3) says that the size of the data should be 28 bytes (8 bytes for
compressed and uncompresed size, and some other fields), but there are programs
that will only store 16 bytes (compressed and uncompressed size).

## Directories unpacked as regular files

Most, if not all, ZIP implementations rely on names of directories being stored
with a `/` at the end of the entry name, even though the official ZIP
specification does not mention that a `/` is mandatory for a directory. It
seems that at some point this just became a convention. For example, the
.NET API seems to rely on it:

<https://github.com/PowerShell/Microsoft.PowerShell.Archive/blob/b783599348e726069f17b90bd490f4f856f661f6/src/ZipArchive.cs#L43>
<https://github.com/dotnet/runtime/blob/96a0fb1cd6210fc4842f32f549870a1d82e95c6f/src/libraries/System.IO.Compression.ZipFile/src/System/IO/Compression/ZipFile.Create.cs#L394>

as does `unzip` (comment from `zip30.tar.gz`, file `unix/unix.c`, line 163):

```
/* Add trailing / to the directory name */
```

Both `unzip` and Python's `zipfile` module rely on having a `/` for directory
names.

There are some ZIP files that contain files where directory names do not end in
`/` and where the standard utilities fail: instead of creating a directory a
zero byte file with the same name as the directory is written. Despite bug
reports being filed this is still a problem. A bug report can be found at:

<http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442>

Trying to unpack the file mentioned in this bug report leads to the following
error with `unzip`:

```
$ unzip 1_06_03P.zip
Archive:  1_06_03P.zip
 extracting: online_upgrade_img
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/bp28v_md5.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/bp28_md5.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/emergency_recovery.sh.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/J120.bp28.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/machine_type.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/md5.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/ouimg.bin.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/ouimg.ver.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/OU_Burner.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/Software_Version.
checkdir error:  online_upgrade_img exists but is not directory
                 unable to process online_upgrade_img/V10X.bp28v.
```

In BANG this is solved by first looking at the "external file attributes"
field from the central directory (section 4.3.12) and checking if the low
order byte corresponds to the MS-DOS directory attribute byte (section 4.4.15)
while also checking that the size recorded for the file is 0 and that Python's
`zipfile` module does not recognize the file as a directory. If this is the
case, then the directory is not unpacked with Python's `zipfile` module, but a
directory with the name of the entry is created instead.

This might not be entirely fool proof, but it seems to be such a very rare edge
case that so far only one example has been found in the wild.

## Multiple entries with the same name

It is possible to have multiple entries in the same ZIP file, with different
properties, for example a copy of a file, and a link with the same name. It
is unclear how these conflicts should be resolved and BANG currently does
not handle this correctly.

## Mismatches between central directory and actual files

There could be more file entries in the archive than listed in the central
directory.
