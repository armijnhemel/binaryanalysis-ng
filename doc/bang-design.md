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

When BANG analyzes a file, it will check whether it can process the file,
whether it is a padding file, whether it can check it by the extension, or
whether it can recognize parts from matching signatures at a specific offset.

The check functions in `process_job` use iterators to yield *meta directories*
(see below), in which they store information about the file. If the file
consists of multiple concatenated files, they will automatically result in
multiple meta directories and record the different files as extracted files in
the main file.

When a file is an archive, the `unpack` method on the `UnpackParser` object
will yield all the unpacked files, which `process_job` then immediately queues.

For each file from the scanning queue the following is done:

1.  check if the file is a regular file, or if it is a special file, like
    a block or character device, a socket file, or if it is a directory.
    Only regular files are scanned.
2.  analyze the file to verify what kind of file it is, and if any data
    can be extracted from it in case it is a container format (file system,
    archive, compresed file, etcetera), or if it is a regular file with data
    appended to it, or prepended in front of it.
3.  compute various checksums (MD5, SHA1, SHA256, optionally TLSH and telfhash)

This is done in a so called *pipe line* (see below), which concatenates the
different kinds of parsers.

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

The UnpackParser class is the base class for recognizing, analyzing and
unpacking files. It has methods to parse, to write information to a meta
directory, and to unpack to a meta directory.

#### Meta directories

The analysis for each file will record metadata, extracted files (if the file
consists of multiple concatenated files), and unpacked files (in case the file
contains files itself).  All this information is stored in a *meta directory*.

The top meta directory is called `root`, and every extracted or unpacked file
will have its own meta directory with its own unique name. The meta directory
will not contain its file, but it refers to by storing the pathname in the meta
directory's `pathname` file. The meta directory's `info.pkl` file contains a
data structure that maps extracted and unpacked paths to other meta
directories. It also contains general metadata and unpacked symlinks.

Unpacked files that have absolute paths can be found under `abs`, while those
with relative paths are under `rel`. Files that are carved from a larger file
are stored in a directory `extracted`.

This structure makes it harder to navigate, but unpacked files will not clutter
the directory structure.

The file `unpacking-examples.md` explains the unpacking structure and the
concept of meta directories in more detail.

#### Pipe lines

Pipe lines are concatenations of parsers.

## Optimizations

There are many optimizations in BANG aimed at reducing disk I/O to allow
scanning of very large collections of files.

* No double parsing: Extracted files that have been parsed already will not be
  parsed again, because the processing code will assign it a fresh meta
  directory in which the UnpackParser can store its information.
* Minimize opening files: A meta directory will open the file and provide a
  file object and the mmap-ed file object to the parsers.
* Pre-parsing checks: UnpackParsers can implement quick heuristic checks before
  doing large parses.

## Reducing I/O with buffers and memoryviews

For some unpackers it has been attempted to reduce memory usage using
techniques described in this blog post:

<https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews>

## Prevent copying data to user space by using `os.sendfile()`

One technique that is used is to copy data from and to files (for example:
temporary files) without copying the data to user space first, but letting
the kernel copy it directly is using `os.sendfile()`. This system call
instructs the kernel to do an "in kernel" copying.

This might be replaced in the future by `os.copy_file_range()`.
