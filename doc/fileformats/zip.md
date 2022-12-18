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

## Encryption

ZIP files can be encrypted. In case an encrypted entry is encountered then
no unpacking is attempted, but only structural checks are done to check
whether or not a file is a complete ZIP file or carving needs to be done.

## Data descriptors

The ZIP specifications say that a file's data can be followed by a so called
"data descriptor" (section 4.3.9) if the bit 3 in the "general purpose bit
flag" (section 4.4.4) is set. If so then, according to the specification:

    If this bit is set, the fields crc-32, compressed 
    size and uncompressed size are set to zero in the 
    local header.  The correct values are put in the 
    data descriptor immediately following the compressed
    data.

This means that the size of an entry is not always known in advance, but has
to be determined. The data descriptor does not have a standard header, but there
is a value that is often associated with it that can be scanned for (section
4.3.9.3). This means that possibly all data in a file entry has to be scanned
for either:

* a common data descriptor header
* a local file header (possibly meaning a new entry is starting)
* another known header (central directory, archive headers)
* the presence of an APK signing block (see next section)

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

## Minimum ZIP versions

Some features in ZIP files were introduced in later versions of ZIP files. The
versions are stored in the local file header (section 4.3.7) and other headers.
The versions (section 4.4.3) can be computed by dividing the value from the
local file header by 10. For example, "version 6.3" will be stored as "63" in
the file header. The latest minimum version that has been defined is 6.3.

There are a few files where the minimum version is something like `0x314` (778)
or similar in the local file header, but not in the central directory. These
known invalid versions are silently ignored in BANG.

## Customized headers

There are some vendors, such as the Chinese IP camera vendor Dahua, that use
the ZIP format, but that slightly change one or more headers. In the case of
Dahua the only change is that the first local file header is changed from
`PK\x03\x04` to `DH\x03\x04`. By changing it to `PK\x03\x04` it can be
unpacked.

## Multiple entries with the same name

It is possible to have multiple entries in the same ZIP file, with different
properties, for example a copy of a file, and a link with the same name. It
is unclear how these conflicts should be resolved and BANG currently does
not handle this correctly.

## Mismatches between central directory and actual files

There could be more file entries in the archive than listed in the central
directory.
