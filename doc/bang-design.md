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

Each file is first unpacked, after which a result is returned. If a file is
unsuccessfully unpacked the following information is kept:

1.  the type of file or data that was unpacked (example: gzip, ext2 file
    system).
2.  the byte range of the unpacked data, indicating where the file or data
    starts and where it ends. This is useful if different files have been
    concatenated (example: a flash dump with different partitions)
3.  paths of any files that were unpacked (example: contents of a ZIP file)
4.  labels describing the unpacked data, which can later be used to more
    quickly identify files and filter using the labels.


### Unpacking

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

#### Interface
