# ZIP file format

This document describes ZIP files and all of the different variants that have
been encountered while working on BANG. While there are some references to
BANG this document is by no means exclusive to BANG and more of a generic
documentation of unclarities in the specifications, differences between
different ZIP implementations, quirks encountered in real life ZIP files and
how some are creatively using the ZIP file format contradicting the official
specifications.

Some of the information in this document has already been published in a blog
post which you can find at:

<http://web.archive.org/web/20180718185811/http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html>

The official ZIP file specification (latest is 6.3.10) can be found at:

<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>

In the rest of this document there will be references to sections in the
official specification.

# ZIP file overview

A ZIP file typically consists of a series of entries, optionally some metadata
related to archives and encryption, followed by a structure called the "central
directory" (section 4.3.6). The central directory essentially serves as a random
access lookup table to provide quick access to the files inside the ZIP archive
because it contains the offsets to the start of each file.

The central directory is then followed by (optional) ZIP64 records and finally
a variable length record called "end of central directory" that contains
(amongst others) the offset from the start of the ZIP data to the central
directory.

## Quick introduction to unpacking ZIP files

Most tools unpack ZIP files as follows:

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
data, or it could be that the other data than expected is unpacked. Two small
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
itself has a maximum of 65,535 bytes.

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
then B) and then unpacked using the standard method (jumping to the end of the
file, finding the central directory and then traversing the central directory)
the central directory of B will be at the end, so only the entries of file B
will be found. To unpack entries from A you need to find out where the central
directory of A is in the file.

A sample file is easily created, by creating another ZIP file and using `cat`
to add the contents of the earlier test file (see first example) and the new
ZIP file to a new combined file:

```
$ zip -r test2.zip /bin/vim
  adding: bin/vim (deflated 48%)
$ cat /tmp/test.zip /tmp/test2.zip > /tmp/test3.zip
```

Different tools process these differently:

`unzip` for example only sees the second archive:

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

`p7zip` on the other hand only sees the first ZIP file and warns about extra
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

BANG parses the files from the start of the file, so first finds A, then B and
unpacks both archives.

The tools mentioned above are not the only ones that behave differently.
Because ZIP is such a widely supported format it is likely that there are
many tools that are implementing unpacking behaviour differently, which
potentially gives bad actors an opportunity. In fact, a few years ago
[malware][double_loaded] was discovered that tried to take advantage of this
to smuggle malicious files past security scanners.

These examples show that even very straightforward uses with valid ZIP files
can confuse unpackers and lead to different results when using different
unpackers. In the ZIP file format specification there are more places where
the specification isn't clear. Sometimes the specifications are clear, but
implementations do not follow the specifications or make assumptions that are
not made in the specifications, which can lead to edge cases, unclarities and
possibly crashes or exploits.

# ZIP file internals

In this section the whole structure of a ZIP file is explained and exceptions
that have been encountered are highlighted.

The central directory in ZIP files are leading. It serves as a lookup table
for entries in the ZIP file. The central directory contains information about
entries in the ZIP file (directories, regular files) in so called "central
directory headers". Each central directory header points to a "local file
header" in the ZIP file, which describes a file and associated file data
(unless it is a directory or an empty file, in wich case there is no associated
file data).

All of the information in the local file header (except the signature) is
replicated in the corresponding central directory header for the file (but the
central directory header will contain also includes some more information). In
a well formed ZIP file these are corresponding. Depending on the field and the
program used for unpacking the data in the local file header might be just
informational, or will be completely ignored.

According to the specification there should be a central directory header
for every local file header:

```
4.3.2 Each file placed into a ZIP file MUST be preceded by a "local
file header" record for that file. Each "local file header" MUST be
accompanied by a corresponding "central directory header" record within
the central directory section of the ZIP file.
```

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

There is a lot of overlap with the "central directory" records which is leading
when unpacking data, so many descriptions below will discuss the field for both
the local file header and the central directory where applicable.

### Local file header signature

The first exception is that there are certain vendors that have changed the
local file header signature. One example is the Chinese IP camera vendor Dahua.
The first local file header is changed from `PK\x03\x04` to `DH\x03\x04`. By
changing the first local file header signature back to `PK\x03\x04` allows
the ZIP file to be unpacked.

### Version needed to extract

The ZIP file format has been under development for many years and new features
have been introduced over time. As older versions of ZIP programs will not be
able to process files with these new features the "version needed to extract"
field can be used to indicate which version of the ZIP feature set should be
implemented to successfully unpack a file. This flag is repeated in various
other headers ("central directory header", "zip64 end of central directory")
as well.

As an example, for ZIP64 files the minimum feature version that the extraction
program needs to implement is `4.5`. If a ZIP64 file is written, then the
program writing the ZIP file needs to set the version needed to extract to
`4.5` or higher. The list of minimum feature versions that have been defined
can be found in section 4.4.3.

Storing a file in a ZIP archive with the `store` method (which only stores it
without any compression) requires version `1.0` to be supported:

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
file these can be (and frequently are) different for each individual entry.
A small example to illustrate:

```
$ mkdir test
$ cp /bin/ls test
$ zip -r test.zip test
updating: test/ (stored 0%)
updating: test/ls (deflated 55%)
$ file test.zip
test.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

This file has a directory stored (minimum version needed: `1.0`) but also
a file compressed with the `deflate` algorithm (minimum version needed: `2.0`).

The `file` command only looks at the first few bytes of the file and only sees
the metadata for the stored directory, but when using `zipinfo -v` (as well
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

Mixing the different versions allow a tool to unpack the data that it can
process, while skipping data that it cannot process.

When reading the ZIP specifications superficially it is easy to miss that the
version flag is actually not a pure version number, but can also contain some
information about the host operating system where the ZIP file was created.
This is explained in sections 4.4.2 and 4.4.3. The upper byte contains the
information about the host operating system or file systems (around 20 have
been defined).

The lower byte contains the actual version number. The version number is not
split in "major/minor" (like in section 4.4.3), but stored in a different way.
To get back to the version in section 4.4.3 the value has to be divided by
`10`. For example, "version 4.6" will be stored as `0x2e` (`46`) in the file
header.

When a ZIP file is created the program that creates the ZIP file can choose
to store the host operating system. Not every tool does this: when using
`unzip` on Linux the host operating system is set to `0`, but `p7zip` sets
it to `3` (Unix), as shown by the following example.

The version of `p7zip` used is:

```
$ 7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)
```

The following command adds the file `ls` to a file `ls.zip`:

```
$ 7z a -tZIP -Pbla ls.zip ls
```

This creates a regular ZIP file:

```
$ file ls.zip
ls.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

The hexadecimal output of the first line of the file looks like this:

```
$ hexdump -C ls.zip | head -n 1
00000000  50 4b 03 04 14 03 01 00  08 00 cc a1 8f 57 57 35  |PK...........WW5|
```

The "minimum version needed to extract" can be found in bytes 5 and 6.
this file the version is `0x314`. The upper byte is the host operating system
(`3`, corresponding to Unix) and the actual version is `0x14` (`20`) which
translates to version `2.0`.

The hexadecimal output of a similar file with the same contents made with
`unzip` looks like this:

```
00000000  50 4b 03 04 14 00 09 00  08 00 cc a1 8f 57 57 35  |PK...........WW5|
```

Here the version is `0x14` (`20`, corresponding to `2.0` in table 4.4.3.2).

`unzip` and `p7zip` seem to ignore the upper byte (host operating system)
even if the value used is not in the ZIP specification (BANG actually does
verify if it is valid).

The lower byte (with the actual version) is checked somewhat, depending on the
program. As it turns out: the value in the local file header does not matter
at all for `unzip`: it looks at the corresponding field in the central
directory instead. As long as the value in the central directory is valid
`unzip` will unpack it. If it isn't then `unzip` refuses to unpack it. `p7zip`
completely ignores the field.

This can be demonstrated by modifying the number in the local file header and
the central directory and checking how tools behave. First create a ZIP file
with a single file and run `file` to see what the minimum version needed to
unpack is in the local file header (it is the same in the central directory
which can be verified using `zipinfo -v`):

```
$ zip -r test.zip /bin/ls
  adding: bin/ls (deflated 55%)
$ file test.zip
test.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

Then modify the local file header using a hexeditor (example: `ghex`) and
change the version needed to `0xaa` (17.0, a currently not existing ZIP
version) and check again:

```
$ file test.zip
test.zip: Zip archive data, at least v17.0 to extract, compression method=deflate
```

`unzip` will happily unpack the file:

```
$ unzip test.zip
Archive:  test.zip
  inflating: bin/ls
```
as will `p7zip`:

```
$ 7z x test.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 64220 bytes (63 KiB)

Extracting archive: test.zip
--
Path = test.zip
Type = zip
Physical Size = 64220

Everything is Ok

Size:       142088
Compressed: 64220
```

Changing the corresponding value in the central directory gives different
results.

`unzip` for example refuses to unpack:

```
$ unzip test.zip
Archive:  test.zip
   skipping: bin/ls                  need PK compat. v17.0 (can do v4.6)
```

but `p7zip` doesn't complain and will unpack the data (even when changing the
version in both local file header and central directory):

```
$ 7z x test.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 64220 bytes (63 KiB)

Extracting archive: test.zip
--
Path = test.zip
Type = zip
Physical Size = 64220

Everything is Ok

Size:       142088
Compressed: 64220
```

The reason why `p7zip` ignores it is likely that it only looks at how the data
is stored or compressed, determines that (in this case) it can unpack the data
and then simply ignores the version number in both the local file header and
the central directory.

A rule of thumb: as long as the data in the central directory is valid the file
can be unpacked by the unpackers tested.

### General purpose bit flag

The general purpose bit flag (section 4.4.4) has a few important bits, namely
"encryption" (bit 0) and "data descriptor" (bit 3). This flag is repeated in
the corresponding central directory header for the file (and is expected to be
the same).

#### Encryption

Entries in ZIP files can be encrypted with a variety of methods. The standard
password encryption in ZIP is weak and prone to a known plaintext attack. If an
entry is encryted with this encryption method then the "encryption" bit in the
general purpose bit flag should have been set.

In case an encrypted entry is found and there is no password available then it
still possible to do structural checks (extract file name, CRC32, and so on)
and verify if the data is sound and skip the encrypted data, while unpacking
data that has not been encrypted (such as directories, which are only stored).

This can be easily demonstrated by building an encrypted ZIP file with a file
inside a directory:

```
$ zip -r test.zip test -e -Ptest
  adding: test/ (stored 0%)
  adding: test/ls (deflated 55%)
```

and then extracting it with `unzip`. If the correct password is not given the
directory (which has not been encrypted, but merely stored) will still be
unpacked/created:

```
$ unzip test.zip
Archive:  test.zip
   creating: test/
[test.zip] test/ls password:
   skipping: test/ls                 incorrect password
```

and no files will have been unpacked:

```
$ ls test/ | wc -l
0
```

Interestingly, and unlike `unzip`, when running `p7zip` an empty placeholder
file will be created:

```
$ 7z x test.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 64388 bytes (63 KiB)

Extracting archive: test.zip
--
Path = test.zip
Type = zip
Physical Size = 64388


Enter password (will not be echoed):
ERROR: Wrong password : test/ls

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

The directory `test` will now contain an empty file:

```
$ find test/ -type f | wc -l
1
$ du -h test/ls
0	test/ls
```

Other encryption methods are stronger. Depending on the encryption method the
encryption bit flag might or might not be set. For example: for AE-x it will
be set (APPENDIX E), while for other encryption methods it might not. The flag
should not be used as the sole indicator of encryption.

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
files from (fairly) recent devices, or encrypted files created with `zip`.

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

### File name length, extra field length, file comment field length

Section 4.4.10 - 4.4.12 document the file name length (local file header and
central directory), extra field length (local file header and central
directory) and the file comment (central directory only). For these fields the
following *optional* restriction is specified:

```
The length of the file name, extra field, and comment
fields respectively.  The combined length of any
directory record and these three fields SHOULD NOT
generally exceed 65,535 bytes.  If input came from standard
input, the file name length is set to zero.
```

In practice this is not a check that should be strictly enforced, as ZIP
implementations tend to completely ignore it. As an example, in Python it
is very easy to create a file where these fields together are larger than
65,535 bytes:

```
>>> import zipfile
>>> z = zipfile.ZipInfo(40000*'a')
>>> z.comment = 65535*b'b'
>>> contents = 10*b'c'
>>> bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
>>> bla.writestr(z, contents)
>>> bla.close()
```

This will create a ZIP archive containing a 10 byte file with a very long file
name (40,000 characters) and a very long comment (65,535 bytes) that together
exceed 65,535 bytes.  Most of the ZIP tools will be able to process a file like
this just fine, for example `zipinfo` (output edited for length, indicated by
`[...]`):

```
Archive:  bla.zip
There is no zipfile comment.

End-of-central-directory record:
-------------------------------

  Zip archive file size:                    145643 (00000000000238EBh)
  Actual end-cent-dir record offset:        145621 (00000000000238D5h)
  Expected end-cent-dir record offset:      145621 (00000000000238D5h)
  (based on the length of the central directory and its expected offset)

  This zipfile constitutes the sole disk of a single-part archive; its
  central directory contains 1 entry.
  The central directory is 105581 (0000000000019C6Dh) bytes long,
  and its (expected) offset in bytes from the beginning of the zipfile
  is 40040 (0000000000009C68h).


Central directory entry #1:
---------------------------

  aaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  offset of local header from start of archive:   0
                                                  (0000000000000000h) bytes
  file system or operating system of origin:      Unix
  version of encoding software:                   2.0
  minimum file system compatibility required:     MS-DOS, OS/2 or NT FAT
  minimum software version required to extract:   2.0
  compression method:                             none (stored)
  file security status:                           not encrypted
  extended local header:                          no
  file last modified on (DOS date/time):          1980 Jan 1 00:00:00
  32-bit CRC value (hex):                         f115ce3f
  compressed size:                                10 bytes
  uncompressed size:                              10 bytes
  length of filename:                             40000 characters
  length of extra field:                          0 bytes
  length of file comment:                         65535 characters
  disk number on which file begins:               disk 1
  apparent file type:                             binary
  Unix file attributes (000600 octal):            ?rw-------
  MS-DOS file attributes (00 hex):                none

------------------------- file comment begins ----------------------------
bbbbbbbbbb[...]bbbbbbbbbbbbbbbbbbbbbbbbb
-------------------------- file comment ends -----------------------------
```

Unpacking might not be possible, as is very likely that the file system itself
has imposed limits on the length of a file name. As an example, when running
`p7zip` to unpack the file the following output is printed (truncated for size
indicated by `[...]`):

```
$ 7z x /tmp/bla.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 86360 bytes (85 KiB)

Extracting archive: /tmp/bla.zip
--
Path = /tmp/bla.zip
Type = zip
Physical Size = 86360

ERROR: Can not open output file : File name too long : ./aaaaaaaaaaaaaaaaaaaaaaa[...]
```

or `unzip`:

```
$ unzip /tmp/bla.zip
Archive:  /tmp/bla.zip
warning:  filename too long--truncating.
warning:  filename too long--truncating.
error:  cannot create aaaaaaaaaaaa[...]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        File name too long
```

#### Displaying file comments

Not every tool displays file comments and there are clear differences between
the tools:

* `unzip` will display the comment (if it contains printable characters) only
  when the `-l` option is used.
* `zipinfo` will display the comment (if it contains printable characters) only
  when the `-v` option is used.
* `p7zip` will not display the comment

#### File comment contents

The Python `zipfile` module documentation says:

```
ZipInfo.comment
    Comment for the individual archive member as a bytes object.
```

Because it is a bytes object it basically means that there are no restrictions
on the *contents* of the file comment itself and any kind of data is accepted
when assembling a ZIP file using Python. For example, embedding a small JPEG
as a file comment is absolutely no problem at all:

```
>>> import zipfile
>>> z = zipfile.ZipInfo(40000*'a')
>>> test_jpeg = open('/tmp/test.jpg', 'rb').read()
>>> len(test_jpeg)
6252
>>> z.comment = test_jpeg
>>> contents = 10*b'c'
>>> bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
>>> bla.writestr(z, contents)
>>> bla.close()
```

or as a script (used below as `test.py`):

```
#!/usr/bin/env python3

import zipfile

z = zipfile.ZipInfo(4*'a')
contents = 10*b'c'
test_jpeg = open('/tmp/test.jpg', 'rb').read()
z.comment = test_jpeg
bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
bla.writestr(z, contents)
bla.close()
```

When expecting the file with `hexdump` it is very easy to see that there
is a JPEG file embedded in the file comment:

```
$ hexdump -C bla.zip | grep JFIF
000138d0  61 61 61 61 61 61 ff d8  ff e0 00 10 4a 46 49 46  |aaaaaa......JFIF|
```

This would allow someone to hide information in the ZIP file that is not
easy to extract unless the ZIP file is parsed in a particular way (and not
with regular unpacking tools).

Trying to write more than 65,535 bytes will result in errors, for example
Python 3.10:

```
$ python3 test.py
Traceback (most recent call last):
  File "/tmp/test.py", line 13, in <module>
    bla.close()
  File "/usr/lib64/python3.10/zipfile.py", line 1839, in close
    self._write_end_record()
  File "/usr/lib64/python3.10/zipfile.py", line 1886, in _write_end_record
    centdir = struct.pack(structCentralDir,
struct.error: ushort format requires 0 <= number <= (0x7fff * 2 + 1)
```

### File name

The file name in ZIP files is defined as follows:

```
4.4.17.1 The name of the file, with optional relative path.
The path stored MUST NOT contain a drive or
device letter, or a leading slash.  All slashes
MUST be forward slashes '/' as opposed to
backwards slashes '\' for compatibility with Amiga
and UNIX file systems etc.  If input came from standard
input, there is no file name field.
```

When the ZIP file format was created the only supported characters were the
ones defined in [IBM Code Page 437][code_page_437] as UTF-8 hadn't been
invented yet. Appendix D in the specification describes how to work with
filenames with other characters.

To store a file name in UTF-8 bit 11 has to be set in the general purpose
flag. Say we have a file name with an UTF-8 file name and add it to a ZIP file:

```
$ zip -r test-korean.zip ㅋㅋㅋ
  adding: ㅋㅋㅋ (stored 0%)
```

#### Mismatched names between local file header and central directory

The name of the file is recorded in both the local file header and the central
directory. These should be the same according to the specification and if these
are not the same, then the file is invalid (according to the specification),
but that's not how the tools behave.

Imagine that there is a ZIP file with the `ls` binary:

```
$ zip -r ls.zip ls
  adding: ls (deflated 55%)
```

and that in the local file header the name is changed to `ll` (for example
using `ghex`) and then moved to a file called `ls-invalid-name.zip`.

The `unzip` program will report that there is a mismatch, but then proceeed
to use the name found in the central directory:

```
$ unzip ls-invalid-name.zip
Archive:  ls-invalid-name.zip
ls:  mismatching "local" filename (ll),
         continuing with "central" filename version
  inflating: ls
```

`p7zip` will not report anything about a mismatch, but simply use the name
from the central directory. `zipinfo` will not report a mismatch but report
the name from the central directory.

Python's `zipfile` will report an error:

```
>>> import zipfile
>>> test_zip = zipfile.ZipFile('ls-invalid-name.zip')
>>> test_zip.extractall()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib64/python3.10/zipfile.py", line 1647, in extractall
    self._extract_member(zipinfo, path, pwd)
  File "/usr/lib64/python3.10/zipfile.py", line 1700, in _extract_member
    with self.open(member, pwd=pwd) as source, \
  File "/usr/lib64/python3.10/zipfile.py", line 1558, in open
    raise BadZipFile(
zipfile.BadZipFile: File name in directory 'ls' and header b'll' differ.
```

#### Directory names

Most (not all) ZIP implementations rely on names of directories being stored
with a `/` at the end of the entry name, even though the official ZIP
specification does not mention that a `/` is mandatory for a directory. At some
point this just became a convention. For example, the .NET API seems to rely on
it:

<https://github.com/PowerShell/Microsoft.PowerShell.Archive/blob/b783599348e726069f17b90bd490f4f856f661f6/src/ZipArchive.cs#L43>
<https://github.com/dotnet/runtime/blob/96a0fb1cd6210fc4842f32f549870a1d82e95c6f/src/libraries/System.IO.Compression.ZipFile/src/System/IO/Compression/ZipFile.Create.cs#L394>

as does `unzip` (comment from `zip30.tar.gz`, file `unix/unix.c`, line 163):

```
/* Add trailing / to the directory name */
```

Python's `zipfile` module also requires it. `p7zip` on the other hand does not.

There actually are some ZIP files that contain files where directory names do
not end in `/` and where most implementations fail: instead of creating a
directory a zero byte file with the same name as the directory is written.
Despite bug reports having been filed this is still a problem. A bug report can
be found at:

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

`p7zip` will correctly unpack the archive:

```
$ 7z x 1_06_03P.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 180253537 bytes (172 MiB)

Extracting archive: 1_06_03P.zip
--
Path = 1_06_03P.zip
Type = zip
Physical Size = 180253537

Everything is Ok

Folders: 1
Files: 12
Size:       190915623
Compressed: 180253537
```

As BANG depends on Python's `zipfile` module (which cannot correctly unpack
these files) some workarounds are needed by first looking at the "external file
attributes" field from the central directory (section 4.3.12) and checking if
the low order byte corresponds to the MS-DOS directory attribute byte (section
4.4.15) while also checking that the size recorded for the file is 0 and that
Python's `zipfile` module does not recognize the file as a directory. If this
is the case, then the directory is not unpacked with Python's `zipfile` module,
but a directory with the name of the entry is created instead.

This might not be entirely fool proof, but it seems to be such a very rare edge
case that so far only one example has been found in the wild.

#### Absolute path names

The use of absolute paths in file names is not allowed according to the
specifications:

```
The path stored MUST NOT contain a drive or
device letter, or a leading slash.
```

In `unzip` it is not possible to create a file with absolute paths, but
creating a file with a leading slash (or even multiple) is absolutely no
problem using Python's `zipfile` module:

```
>>> import zipfile
>>> z = zipfile.ZipInfo('/tmp/absolute')
>>> contents = 10*b'c'
>>> bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
>>> bla.writestr(z, contents)
>>> bla.close()
```

`unzip` will unpack this to a relative path but also issue a warning:

```
$ unzip /tmp/bla.zip
Archive:  /tmp/bla.zip
warning:  stripped absolute path spec from /tmp/absolute
 extracting: tmp/absolute
```

`p7zip` will also correctly unpack the file, but not issue a warning:

```
$ 7z x /tmp/bla.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz (506E3),ASM,AES-NI)

Scanning the drive for archives:
1 file, 134 bytes (1 KiB)

Extracting archive: /tmp/bla.zip
--
Path = /tmp/bla.zip
Type = zip
Physical Size = 134

Everything is Ok

Size:       10
Compressed: 134
```

Python's `zipfile` will also correctly unpack the file, but issue no warning.

#### Names containing current or parent directories

The ZIP specifications do not say anything about paths containing the current
directory (`.`) or the parent directory (`..`). The only thing that is said is:

```
The name of the file, with optional relative path.
The path stored MUST NOT contain a drive or
device letter, or a leading slash.
```

As both `.` and `..` are relative paths this could be interpreted
to read that that these paths are valid.

Creating a file with any of these paths is trivial using Python's `zipfile`
module:

```
>>> import zipfile
>>> z = zipfile.ZipInfo('../../.././tmp/relative')
>>> contents = 10*b'c'
>>> bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
>>> bla.writestr(z, contents)
>>> bla.close()
```

The relative path with the current and parent directory will be stored in the
file:

```
$ unzip -l /tmp/bla.zip
Archive:  /tmp/bla.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       10  01-01-1980 00:00   ../../.././tmp/relative
---------                     -------
       10                     1 file
```

`unzip` processes this file but issues a warning:

```
$ unzip /tmp/bla.zip
Archive:  /tmp/bla.zip
warning:  skipped "../" path component(s) in ../../.././tmp/relative
 extracting: tmp/relative
```

`p7zip` extracts the file without a warning.

Both implementations will strip all `..` components and basically rewrite
the filename from `../../.././tmp/relative` to `tmp/relative`.

Other ZIP implementations might not and this could be used for a path traversal
attack. This is actually a very old attack [dating back to 1991][phrack]
although it was [rediscovered in 2018 as Zip Slip][zip_slip] with
[many implementations affected][zip_slip_2].

#### Multiple entries with the same name

It is possible to have multiple entries in the same ZIP file, with different
properties, for example a copy of a file, and a link with the same name. It
is unclear how these conflicts should be resolved.

A simple test script to add a file with the same entries:

```
#!/usr/bin/env python3

import zipfile

z = zipfile.ZipInfo(4*'a')
contents = 10*b'c'
bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
bla.writestr(z, contents)
bla.writestr(z, contents)
bla.writestr(z, contents)
bla.close()
```

This script adds a file called `aaaa` to an archive three times. When running
this script Python's `zipfile` module issues a warning:

```
$ python3 test.py
/usr/lib64/python3.10/zipfile.py:1519: UserWarning: Duplicate name: 'aaaa'
  return self._open_to_write(zinfo, force_zip64=force_zip64)
```

but it will write the file with three files, as can be seen when running
`zipinfo`:

```
$ zipinfo bla.zip
Archive:  bla.zip
Zip file size: 304 bytes, number of entries: 3
?rw-------  2.0 unx       10 b- stor 80-Jan-01 00:00 aaaa
?rw-------  2.0 unx       10 b- stor 80-Jan-01 00:00 aaaa
?rw-------  2.0 unx       10 b- stor 80-Jan-01 00:00 aaaa
3 files, 30 bytes uncompressed, 30 bytes compressed:  0.0%
```

`unzip` refuses to unpack the file more than once, except when forced:

```
$ unzip bla.zip
Archive:  bla.zip
 extracting: aaaa
error: invalid zip file with overlapped components (possible zip bomb)
 To unzip the file anyway, rerun the command with UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE environmnent variable
```

When the environment variable is set the user will be asked what to do (here
the `All` option was chosen):

```
$ UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE unzip bla.zip
Archive:  bla.zip
 extracting: aaaa
replace aaaa? [y]es, [n]o, [A]ll, [N]one, [r]ename: A
 extracting: aaaa
 extracting: aaaa
```

`p7zip` will also query the user whether to overwrite the files or not.

### Extra fields

The "extra fields" are a way to store some more metadata for individual files
in the local file header and/or central directory. Typically what is stored
are more granular timestamps (Unix, NTFS), permissions (Unix), 64-bit
extensions, Unicode data or program specific data to give hints that an
unpacker can use to better unpack the data.

The extra fields defined by PKWARE are found in section 4.5, while third party
fields are described in section 4.6 (this list is not complete and there are
more, see `zip.ksy` in the BANG Git repository).

Not all unzip programs have support for all the extra fields. Some common ones,
such as the Unix permission fields, are widely supported. The extra fields that
are not recognized can be skipped by a reader that doesn't support these
fields.

## File data

The file data is typically just a blob of data. If the file is encrypted an
extra encryption header will be in front of the data. Otherwise it is just a
blob that, depending on the compression used, could be unpacked without using
the central directory at all (which is something that BANG can do).

## End of central directory

The "end of central directory" indicates the end of the ZIP file. It contains
important information, such as the start of the central directory, which is not
fixed. The "end of central directory" record itself is also not fixed in size,
because there is a variable part, namely the .ZIP file comment field (see also
the introduction at the top of this document).

```
end of central dir signature    4 bytes  (0x06054b50)
number of this disk             2 bytes

number of the disk with the
start of the central directory  2 bytes

total number of entries in the
central directory on this disk  2 bytes

total number of entries in
the central directory           2 bytes
size of the central directory   4 bytes

offset of start of central
directory with respect to
the starting disk number        4 bytes
.ZIP file comment length        2 bytes
```

Schematically the static part looks like this:

```
+------+------+------+------+------+------+------+------+------+------+------+------+
|  P   |   K  | 0x05 | 0x06 | this disk   | disk with   | total files | total files |
|      |      |      |      |             | central dir | on this disk|             |
+------+------+------+------+------+------+------+------+------+------+------+------+
| total files | size of     | offset to central dir     | comment     |
|             | central dir |                           | size        |
+------+------+------+------+------+------+------+------+------+------+
```

The static part is followed by a variable part:

```
.ZIP file comment       (variable size)
```

### .ZIP file comment

The end of central directory has room for a comment. Like the comments for
individual ZIP file entries it has a maximum size of 65,353 bytes (with no
restriction on the *contents* of the comment):

```
.ZIP file comment length        2 bytes
.ZIP file comment       (variable size)
```

Python's `zipfile` documentation says:

```
ZipFile.comment
    The comment associated with the ZIP file as a bytes object. If assigning a
    comment to a ZipFile instance created with mode 'w', 'x' or 'a', it should
    be no longer than 65535 bytes. Comments longer than this will be truncated.
```

The following test script (in this example stored in `/tmp/test.py`) tries to
add more than the maximum amount of bytes:

```
#!/usr/bin/env python3

import zipfile

z = zipfile.ZipInfo(4*'a')
contents = 10*b'c'
bla = zipfile.ZipFile('/tmp/bla.zip', mode='w')
bla.writestr(z, contents)
comment = 70000*b'b'
bla.comment = comment
bla.close()
```

Python 3.10 and 3.11 will display the following warning:

```
/tmp/test.py:10: UserWarning: Archive comment is too long; truncating to 65535 bytes
  bla.comment = comment
```

and then exit gracefully. Inspection of the file reveals that indeed only
65,535 bytes are in the comment field.

## ZIP64

The size field in the local file header cannot store a number larger than
4,294,967,295 bytes (4 bytes, maximum `0xffffffff`). If a file is equal to or
larger than this number the actual size is stored in the "extra field" in the
local file header (section 4.3.7). Storing files with file sizes equal to or
larger than this limit is referred to as ZIP64. The specification of ZIP64
(section 4.5.3) says that the size of the data should be 28 bytes (8 bytes for
compressed and uncompressed size, and some other fields), but there are programs
that will only store 16 bytes (compressed and uncompressed size).

ZIP64 files are easy to create, even without the need for a 4 GiB sized file,
by streaming the file:

```
$ cat /bin/ls | zip -r /tmp/bla.zip -
  adding: - (deflated 55%)
$ file bla.zip
bla.zip: Zip archive data, at least v4.5 to extract, compression method=deflate
```

At the end of the file the ZIP64 end of central directory record and the ZIP64
end of central directory locator can be found at the end of the file.

# Non-compliant ZIP files

There are ZIP files that are strictly speaking not compliant with the ZIP
specification but which can still be unpacked (partially) successfully by
many of the standard ZIP-utilities. This is because many of the tools rely
on the central directory to decide what to unpack. The central directory acts
as a lookup table, but there are no checks to see if any data has been wedged
in between the different entries in the ZIP file and if the data in the ZIP
file before the central directory is contiguous, or if the number of entries
in the central directory matches the amount of files in the file.

The specification has the following diagram for the structure of a ZIP file
in section 4.3.6:

```
[local file header 1]
[encryption header 1]
[file data 1]
[data descriptor 1]
.
.
.
[local file header n]
[encryption header n]
[file data n]
[data descriptor n]
[archive decryption header]
[archive extra data record]
[central directory header 1]
.
.
.
[central directory header n]
[zip64 end of central directory record]
[zip64 end of central directory locator]
[end of central directory record]
```

This diagram seems to suggest that no random data is allowed between the
different entries in the file although it isn't mentioned in the text
explicitly.

## Android APK with APK signing blocks

Android APK files are essentially ZIP files. To increase security Google added
signatures, or so called "APK signing blocks". Three versions have been
published so far. Since there is no standard header in the ZIP file format for
this information Google decided to add it after the last data descriptor and
before the central directory.

Unpacking with regular unpacking programs works because they will simply read
the central directory to get the offsets for the individual file entries. As
long as the offsets in the central directory are correct it doesn't really
matter how much extra data is in the file and where this data is in the ZIP file
(except, of course, BANG, which takes a slightly approach).

In some files the APK signing block is aligned to 4096 bytes:

<https://android.googlesource.com/platform/tools/apksig/+/24aeb9bff8b6479397960eadac9283cc8a509f0b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#851>

If this is the case, then there will be a padding block identifier:

<https://android.googlesource.com/platform/tools/apksig/+/24aeb9bff8b6479397960eadac9283cc8a509f0b/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#98>

but this identifier doesn't appear at the start of the signing block, but at
the end (which makes sense when reading from the end of the file).

Google could have chosen some more standard mechanisms available in the ZIP
standard: every APK could have been a ZIP64 files and the "zip64 extensible
data sector" field in the "Zip64 end of central directory record" could have
been used. Alternatively the "digital signature" header or the "Archive extra
data record" could have been used.

Some of these features require a ZIP implementation that supports these headers
and not all implementations do, so it could be that for maximum backwards
compatibility this mechanism was chosen, even if it meant relying on an
unclarity in the ZIP specifications.

## Seek-Optimized ZIP

A fairly obscure format is the "Seek-Optimized ZIP" format, or [SOZip][sozip].
This format, originating in the geospatial workd, adds extra files to the ZIP
file that contain metadata that can be used for quick random access for
compressed data. This metadata is added as regular files, but without a
corresponding entry in the central directory. A SOZip-aware reader can use
these files to do quick seeks in the file and a reader that is not aware will
not notice these files and ignore them.

This is explicitly not allowed according to section 4.3.2:

```
4.3.2 Each file placed into a ZIP file MUST be preceded by  a "local
file header" record for that file.  Each "local file header" MUST be
accompanied by a corresponding "central directory header" record within
the central directory section of the ZIP file.
```

Every unpacker tested (`unzip`, `p7zip`, Python's `zipfile`) ignores the
extra files.

The extra files are metadata, not actual files. A correct unpacker should
probably write these extra files to a different location than the contents of
the ZIP file.

# Appendix: ZIP file unpacking in BANG

In BANG it is assumed that ZIP files are always followed by extra data and
need to be carved, so parsing starts from the beginning of the file, instead of
using only the central directory of the ZIP file to locate and access the
files.

FIles are unpacked using Python's `zipfile` module so then the central
directory will of course be used.

ZIP file unpacking in BANG works as follows (simplified):

1. open the file at a specific offset (namely where a local file header was
   found)
2. go to the start of the first local file header (section 4.3.7)
3. try to parse the entire file using the Kaitai Struct grammar
4. extract contents using Python's `zipfile` module, unless the file
   is encrypted

If parsing using the Kaitai Struct grammar is not successful, then the
following steps are taken (some steps are performed using Kaitai Struct,
see the code):

1. open the file at a specific offset (namely where a local file header was
   found)
2. go to the start of the first local file header (section 4.3.7)
3. read and parse the data in a local file header
4. skip the compressed data
5. process all ZIP entries and any optional extra data such as APK signing
   blocks, until a central directory is found (section 4.3.12)
6. process the central directory and verify if the contents in the central
   directory correspond to the entries found in step 5.
7. verify if there is an end of central directory (section 4.3.16)
8. carve the ZIP file (if necessary) or replace headers (example: Dahua
   firmware files)
9. extract contents using Python's `zipfile` module, unless the file
   is encrypted

This (simplified) workflow is enough to process almost all ZIP files found
in or used for firmware archives.

In case BANG cannot unpack a ZIP file it will try to unpack individual records
(stored, deflate, bzip2 and LZMA).

[double_loaded]:https://web.archive.org/web/20191107134232/https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/double-loaded-zip-file-delivers-nanocore/
[phrack]:http://phrack.org/issues/34/5.html
[zip_slip]:https://security.snyk.io/research/zip-slip-vulnerability
[zip_slip_2]:https://github.com/snyk/zip-slip-vulnerability
[code_page_437]:https://en.wikipedia.org/wiki/Code_page_437
[sozip]:https://github.com/sozip/sozip-spec
