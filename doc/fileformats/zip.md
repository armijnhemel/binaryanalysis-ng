# ZIP file format

This document describes how BANG unpacks ZIP files. Some of the information has
already been published in a blog post which you can find at:

<http://web.archive.org/web/20180718185811/http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html>

The official ZIP file specification can be found at:

<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>

In the rest of this document there will be references to sections in the
official specification.

## ZIP file overview

A ZIP file consists of a series of entries, followed by a central directory,
with extra meta information about these entries. The central directory
essentially serves as a lookup table to provide quick access to the files inside
the ZIP archive.

In most cases unpacking ZIP compressed data comes down to:

1. opening the file
2. go to the end of the file
3. read and parse the "end of central directory record" (section 4.3.16)
4. jump to the start of the central directory (section 4.3.12)
5. parse the entries in the central directory, determine types and offsets of
   each individual entry and extract the entries

This only works because the central directory can be found. If this is not the
case, then the data cannot be unpacked, or the wrong data is unpacked. Two
examples can illustrate this.

### Example 1: ZIP file with extra data after the central directory

If extra data is appended to a file, even if it is just a single extra byte
then the method as described above does not work and it becomes necessary to
first find out where the ZIP file starts and ends, carve it from the larger
file and then unpack.

### Example 2: Two concatenated ZIP files

Imagine that there are two ZIP files A and B. When these are concatenated (A,
then B) and then unpacked using the standard method the central directory of
B will be at the end, so only the entries of file B will be found. To unpack
entries from A you need to find out where A ends.

# ZIP file unpacking in BANG

In BANG it is assumed that ZIP files are always followed by extra data, so
parsing starts from the beginning of the file, instead of using the central
directory of the ZIP file to access the files.

ZIP file unpacking in BANG works as follows (simplified):

1. open the file
2. go to the start of a local file header (section 4.3.7)
3. read and parse the data in a local file header
4. skip the compressed data
5. process all entries and store information about the entries, until a central
   directory is found (section 4.3.12)
6. process the central directory and verify if the contents in the central
   directory correspond to the entries found in step 5.
7. verify if there is an end of central directory (section 4.3.16)
8. carve the ZIP file (if necessary) and process using standard tools
   (Python's built-in ZIP module)

This (simplified) workflow works well, but as it turns out there are quite a
few exceptions that make it a lot trickier.

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
with a `/` at the end of the entry name (even though the specification does not
seem to mandate this). There are files that contain files where a directory
name does not end in `/` and which make the standard utilities fail and where
instead of a directory a zero byte file with the same name as the directory is
created. Despite bug reports being filed this is still a problem. A bug report
can be found at:

<http://web.archive.org/web/20190814185417/https://bugzilla.redhat.com/show_bug.cgi?id=907442>

Trying to unpack the file mentioned in this bug report leads to the following
error (on Fedora 30):

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

In BANG this is solved by first looking at the "external file attributes"
field from the central directory (section 4.3.12) and checking if the low
order byte corresponds to the MS-DOS directory attribute byte (section 4.4.15)
while also checking that the size is 0 and that Python's zipinfo module does
not recognize the file as a directory. If this is the case, then the directory
is not unpacked with Python's `zipinfo` module, but a directory with the name of
the entry is created instead.

This might not be entirely fool proof, but it is a very rare edge case.

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

There are some vendors, such as the Chinese vendor Dahua, that use the ZIP
format, but that slightly change one or more headers. In the case of Dahua the
only change is that the first local file header is changed from `PK\x03\x04`
to `DH\x03\x04`.

## Multiple entries with the same name

It is possible to have multiple entries in the same ZIP file, with different
properties, for example a copy of a file, and a link with the same name. It
is unclear how these conflicts should be resolved and BANG currently does
not handle this correctly.

## Mismatches between central directory and actual files

There could be more file entries in the archive than listed in the central
directory.
