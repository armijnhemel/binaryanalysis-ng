# BANG design document

Binary Analysis Next Generation (BANG) is a framework for unpacking files (like
firmware) recursively and running checks on the unpacked files. Its intended
use is to able to find out the provenance of the unpacked files and
classify/label files, making them available for further analysis.

This file explains the design of the program and how to write new unpackers
for certain file types.

## Why BANG?

There are quite a few open source licensed tools out there for analyzing
firmware files. Most of these focus on either forensics, or on unpacking
firmware, but none of them focus specifically on where open source, firmware
reverse engineering and security meet.

Experience creating earlier tools shows that the sometimes simplistic and
naive approaches from other tools (assuming correct files instead of broken
data, reliance on magic headers) is not realistic.

## Framework

The main part of the program is (currently) the scan queue and the result
queue. This is where the paths of the files that need to be processed are
stored. There are various threads (configurable) that pick tasks from the
scan queue, analyze the file, write the result to the result queue, and move
on to the next file, until no files are left to be processed.

In case in a scan files are unpacked (from for example a ZIP file) then
these files are added to the scan queue as well.

This works because unpacking a single file is completely independent and
does not rely on unpacking other files (although in some cases the presence
of other files might be needed).

After all files have been unpacked results regarding unpacking are written
to an output file and the files can be further analyzed by other scripts.

### Unpacking

For each file from the scanning queue the following is done:

1.  check if the file is a regular file, or if it is a special file, like
    a block or character device, a socket file, or if it is a directory.
    Only regular files are scanned.
2.  analyze the file to verify what kind of file it is, and if any data
    can be extracted from it in case it is a container format (file system,
    archive, compresed file, etcetera), or if it is a regular file with data
    appended to it, or prepended in front of it.
3.  compute various checksums (MD5, SHA1, SHA256, optionally TLSH and telfhash)

Many file types have a certain header that indicates what file type they
are. On Linux systems these file types are typically described in a
file type database like `/usr/share/magic`. Examples would be gzip, or GIF.

But this is not true for every file type where other information has to
be used, such as a known extension (quite popular on for example Android
and other Google products).

There are three different types of files that can currently be unpacked:

1.  files with a known extension, but without a known magic header. This is
    for for example Android sparse data image formats (for example "protobuf"
    files), or several other Android or Google formats (Chrome PAK, etc.)
2.  files which are inspected for known headers, after which several checks
    are run and data is possibly carved from a larger file.
3.  text only files, where it is not immediately clear what
    is inside and where the file possibly first has to be
    converted to a binary (examples: Intel Hex).

The files are scanned in the above order to prevent false positives as much
as possible. Sometimes extra information will be used to make a better guess.

There are two types of unpackers:

1. legacy unpackers, where parsing and unpacking are combined
2. modern unpackers, where parsing and unpacking have been split

The former are currently still supported, but are being replaced by the
latter. In a future rewrite the legacy unpackers will no longer be supported.

#### Legacy unpackers

Each legacy unpacker has a specific interface:

def unpacker(fileresult, scanenvironment, offset, unpackdir)

1.  fileresult: an object containing information about the file, including
    the full file name, file size, parent object, and so on
2.  scanenvironment: an object containing information about the scan
    environment
3.  offset: offset inside the file where the file system, compressed
    file media file possibly starts
4.  unpackdir: the target directory where data should be written to

For each file that is successfully unpacked, a result is returned in the
form of a dictionary, containing the following fields:

* unpack status (boolean) to indicate whether or not any data was
  unpacked

1.  unpack size to indicate what part of the data was unpacked
2.  a list of tuples (file, labels) that were unpacked from the file.
    The labels could be used to indicate that a file has a certain
    status and that it should not be unpacked as it is already known
    what the file is (example: PNG)
3.  a list of labels for the file
4.  a dict with extra information (structure depending on type
    of scan)
5.  (optional) offset indicating the start of the data

If a file is successfully unpacked the above information is used to store
the following about the unpacked data:

1.  the type of file or data that was unpacked (example: gzip, ext2 file
    system).
2.  the byte range of the unpacked data, indicating where the file or data
    starts and where it ends. This is useful if different files have been
    concatenated (example: a flash dump with different partitions)
3.  paths of any files (and sometimes directories, symbolic links and special
    files) that were unpacked (example: contents of a ZIP file)
4.  labels describing the unpacked data. These can later be used to more
    quickly identify files and run specific checks on them.

If a file is not successfully unpacked the result will contain an error
message, as well as the offset at which place in the file the error occured
which is stored in a log file for later analysis, if needed. The result will
then be:

* a dict with a possible error.

The error dict has the following items:

1.  fatal: boolean to indicate whether or not the error is a fatal
    error (such as disk full, etc.) so BANG should be stopped.
    Non-fatal errors are format violations (files, etc.)
2.  offset: offset where the error occured
3.  reason: human readable description of the error

##### Legacy unpacker return values

The data that is returned from the legacy unpackers is a dictionary with
a key "status" and various other elements, depending whether a scan was
successful or not. If the scan was successful, then the following fields
will also be present:

*   length: an integer indicating the size of the data that is unpacked
*   list of files and labels: a list of tuples with the name of each file
    that was unpacked, plus a list of associated labels (empty most of the time)
*   labels: a list of labels for the file that was scanned
*   offset (optional): an offset where the data starts. Only needs to be set
    if the offset where the data starts isn't the offset that was given as a
    parameter (example: coreboot images)
*   metadata (optional): a data structure with scan specific information.
    Example scans that have this: unpack_elf and unpack_png

If the scan was unsuccessful then the dictionary will contain:

*   error message: a dictionary with information about possible errors that
    occured.

An error message is a dictionary, with the following elements:

*   offset: offset in the file at which the error occured
*   fatal: boolean indicating whether or not the error is fatal and the
    program should be stopped (this is currently ignored)
*   reason: a human readable description of the error

An example of an error message:

    {'offset': 0, 'fatal': False, 'reason': 'invalid PNG data according to PIL'}

#### Unpacking directory

Files that are unpacked from a container, or which are carved from a
larger file are written in a directory structure that looks like this:

    $filename-$type-$counter/

for example:

    example.gz-gzip-1/

For each subsequent gzip file that is unpacked from the file the counter
will be increased, for example:

    example.bin-gzip-1/
    example.bin-gzip-2/
    example.bin-gzip-3/

and so on.

Not every successful verification of a file will have a directory structure
like this. If the entire file is a file from which nothing can be unpacked,
then the directory will not be returned. Examples of this are graphics files
(PNG, GIF, JPEG, WebP, etcetera) or audio files.

Files that have been unpacked are written to this directory and when returned
will be added to the scanning queue.

The offsets of the data inside the original file and the size will be stored
in internal data structures with metadata.

#### Carving

Carving a file from a larger file is a bit different than unpacking data
from a file. The code that carves data from a file already verifies the data
to find the end of the data. Files that are marked as "unpacked" are not
processed by BANG as an optimization.

#### Data stored

The data generated during the scan is separated in two parts:

1. data describing the structure of the data, as well as certain metadata (UID,
   GID, permissions, parent file, offset in the archive, etc.)
2. data specific to the file

The difference between the two is that the latter will always be the same
(except when the scanner changes), while the former can change: an ELF
executable can be included in two different files, but with different
permissions, different ownership, and so on. The data specific to the file
(the contents) wouldn't change, but the metadata would.

The structure of the scan is stored in a Python pickle file called
"bang.pickle" found at the top level of the scan directory. The file
specific data is stored as Python pickle files in the directory "results"
found at the top level of the scan directory.

## Optimizations

There are many optimizations in BANG aimed at reducing disk I/O to allow
scanning of very large collections of files.

In the main scaning loop some checks from the unpacking checks are duplicated
to perform a look ahead during the search for magic headers to see if the magic
headers really are valid, or if they are false positives. This is to prevent
that methods are run unnecessarily. Method calls in Python are quite expensive
and preventing large amounts of them can easily shave a few minutes off for
large files (for example: Android firmwares).

Carving some file types means parsing the file format (example: PNG, Java class
files, etcetera). To prevent these files being scanned again they are
explicitly flagged as already having been scanned.

## Reducing I/O with buffers and memoryviews

For some unpackers it has been attempted to reduce memory usage
using techniques described in this blog post:

<https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews>

## Prevent copying data to user space by using `os.sendfile()`

One technique that is used is to copy data from and to files (for example:
temporary files) without copying the data to user space first, but letting
the kernel copy it directly is using `os.sendfile()`. This system call
instructs the kernel to do an "in kernel" copying.

This might be replaced in the future by `os.copy_file_range()`.
