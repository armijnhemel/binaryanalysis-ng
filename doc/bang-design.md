# BANG design document

Binary Analysis Next Generation (BANG) is a framework for unpacking files (like
firmware) recursively and running checks on the unpacked files. Its intended
use is to able to find out the provenance of the unpacked files and
classify/label files, making them available for further analysis.

This file explains the design of the program and how to write new unpackers
for certain file types.

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
to an output file and the files can be further analyzed.

### Unpacking

For each file from the scanning queue the following is done:

1.  check if the file is a regular file, or if it is a special file, like
    a block or character device, a socket file, or if it is a directory.
    Only regular files are scanned.
2.  compute various checksums (MD5, SHA1, SHA256)
3.  analyze the file to verify what kind of file it is, and if any data
    can be extracted from it in case it is a container format (file system,
    archive, compresed file, etcetera), or if it is a regular file with data
    appended to it, or prepended in front of it.

Many file types have a certain header that indicates what file type they
are. On Linux systems these file types are typically described in a
file type database like /usr/share/magic. Examples would be gzip, or GIF.

But this is not true for every file type where other information has to
be used, such as a known extension (quite popular on for example Android
and other Google products).

There are three different types of files that can currently be unpacked:

1.  files with a known extension, without a known magic header. This is
    for for example Android sparse data image formats, or several other
    Android or Google formats (Chrome PAK, etc.)
2.  blobs, searching for known magic headers and carving them blobs, or
    regular files.
3.  text only files, where it is not immediately clear what
    is inside and where the file possibly first has to be
    converted to a binary (examples: Intel Hex).

The files are scanned in this exact order to prevent false positives.

For each file that is unpacked, a result is returned. If a file is
unsuccessfully unpacked the following information is kept:

1.  the type of file or data that was unpacked (example: gzip, ext2 file
    system).
2.  the byte range of the unpacked data, indicating where the file or data
    starts and where it ends. This is useful if different files have been
    concatenated (example: a flash dump with different partitions)
3.  paths of any files that were unpacked (example: contents of a ZIP file)
4.  labels describing the unpacked data, which can later be used to more
    quickly identify files and filter using the labels.

If a file is not successfully unpacked the result will contain an error
message, as well as the offset at which place in the file the error occured
which is stored in a log file for later analysis, if needed.

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

#### Carving

Carving a file from a larger file is a bit different than unpacking data
from a file. The code that carves data from a file already verifies the data
to find the end of the data. Files that are marked as "unpacked" are not
processed by BANG as an optimization.

#### Return values

The data that is returned from the unpackers carvers is a dictionary with
a key "status" and various other elements, depending whether a scan was
successful or not. If the scan was successful, then the following fields
will also be present:

*   length: an integer indicating the size of the data that is unpacked
*   list of files and labels: a list of tuples with the name of each file
    that was unpacked, plus a list of associated labels (empty most of the time)
*   labels: a list of labels for the file that was scanned

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

#### Optimizations

There are various optimizations in BANG. One optimization is that during the
search for magic headers some sanity checks are performed to see if the magic
headers really are valid, or if they are false positives. This is to prevent
that methods are run unnecessarily. Method calls in Python are quite expensive
and preventing large amounts of them can easily shave a few minutes off for
large files (for example: Android firmwares).

In the main scaning loop some checks from the unpacking checks are duplicated
to essentially perform a look ahead.
