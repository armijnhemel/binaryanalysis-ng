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
directory" (section 4.3). The central directory essentially serves as a lookup
table to provide quick access to the files inside the ZIP archive.

In most cases unpacking ZIP data comes down to:

1. open the file
2. jump to the end of the file
3. search for and parse the "end of central directory record" (section 4.3.16)
4. jump to the start of the central directory relative to the start of the ZIP
   file (section 4.3.12)
5. parse the entries in the central directory, determine types and offsets of
   each individual entry and extract the entries

This method works if the central directory can be found at the end of the file
and is correct. If this is not the case, then the data cannot be unpacked, or
the wrong data is unpacked. Two examples can illustrate this.

### Example 1: ZIP file with extra data after the central directory

If extra data is appended to a file, then the method as described above does
not always work with most popular ZIP tools or unpacking libraries, as
illustrated by the following example.

First create a ZIP file:

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

Then add extra data:

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

For the `unzip` programma used on Fedora (UnZip 6.00) the limit is `67633`
bytes, which can be verified as follows. When adding `67633` bytes `unzip` will
still work:

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

The `zipfile` module in Python 3.10 has a different limit of extra data that
is allowed, namely 65536 bytes, which is the maximum length of the ZIP file
comment (section 4.3.16).

If there is more data than what the tools or libraries allowed and data still
needs to be unpacked from the ZIP file, then it becomes necessary to find out
where the ZIP file starts and ends, and then unpack all the data.

### Example 2: Two concatenated ZIP files

Imagine that there are two ZIP files A and B. When these are concatenated (A,
then B) and then unpacked using the standard method the central directory of
B will be at the end, so only the entries of file B will be found. To unpack
entries from A you need to find out where the central directory of A resides.
This can only be done by parsing from the beginning of the file.

# ZIP file unpacking in BANG

In BANG it is assumed that ZIP files are always followed by extra data, so
parsing starts from the beginning of the file, instead of using the central
directory of the ZIP file to access the files.

ZIP file unpacking in BANG works as follows (simplified):

1. open the file
2. go to the start of a local file header (section 4.3.7)
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
+------+------+------+------+------+------+------+------+
|  P   |   K  | 0x03 | 0x04 | version     | flag        |
+------+------+------+------+------+------+------+------+
| compression | mod time    | mode date   | crc32       |
+------+------+------+------+------+------+------+------+
| crc32 (ctd) | compressed size           | unc. size   |
+------+------+------+------+------+------+------+------+
| unc. size   | name length | extra length|
+------+------+------+------+------+------+
```

The static part if followed by a variable part:

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
does), as the unpacking tools and libraries primarily use the data in the
central directory.

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
If this bit is set, the fields crc-32, compressed
size and uncompressed size are set to zero in the
local header.  The correct values are put in the
data descriptor immediately following the compressed
data.
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

* data descriptor signature
* a local file header
* another known header (central directory, archive headers)
* APK signing block

and then processing the data descriptor it should be possible to correctly
determine the size. Verifications of the size in the data descriptor to see
if it is correct should be done to prevent bogus data. For example, it could
be that another ZIP file could be stored in the entry, so when encountering
for example a local file header it might not be of the next entry but that
of an embedded ZIP file.

In BANG there are various sanity checks in place to detect this.

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
specification does not mention that a `/` is mandatory for a directory. Both
`unzip` and Python's `zipfile` module rely on having a `/` for directory names.

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
