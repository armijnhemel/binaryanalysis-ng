# ZIP file format

This document describes how BANG unpacks ZIP files. Some of the information has
already been published in a blog post which you can find at:

http://web.archive.org/web/20180718185811/http://binary-analysis.blogspot.com/2018/07/walkthrough-zip-file-format.html

The official ZIP file specification can be found at:

https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

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

ZIP file unpacking in BANG works as follows (simplified):

1. the file is opened
2. go to the start of a local file header (section 4.3.7)
3. read and parse the data in a local file header
4. skip over the compressed data
5. process all entries and store information about the entries, until a central
   directory is found (section 4.3.12)
6. process the central directory and verify if the contents in the central
   directory correspond to the entries found in step 5.
7. verify if there is an end of central directory (section 4.3.16)
8. carve the ZIP file (if necessary) and process using standard tools
   (Python's built-in ZIP module)

This (simplified) workflow works well, but as it turns out there are quite a
few exceptions that make it a lot trickier.

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
4.3.9.3).

## APK signing blocks

Android APK files are essentially ZIP files. To increase security Google added
signatures, or so called "APK signing blocks". Three versions have been
published so far. Since there is no standard header to put this information in
Google decided to add it after the last data descriptor and before the central
directory. Even though this is not allowed according to the specifications it
will work because every unpacking program (except BANG) will simply read the
central directory to get the offsets for the individual file entries. As long
as the offsets in the central directory are correct it doesn't really matter
how much extra data is in the file.
