# BANG design document

Binary Analysis Next Generation (BANG) is a framework for unpacking files (like
firmware files) recursively and running analysis tools on the unpacked files.
Its intended use is to able to find out the provenance of the unpacked files
and classify/label files, making them available for further analysis.

This file explains the design of the program and how to write new unpackers
for certain file types.

## Why BANG?

There are quite a few open source licensed tools out there for analyzing
firmware files. Most of these focus on either forensics, or on unpacking
firmware, but none of them focus specifically on where open source, firmware
reverse engineering and security meet.

Experience creating earlier tools shows that the sometimes simplistic and
naive approaches from other tools (assuming correct files instead of broken
data, reliance on magic headers, assuming a single file only contains one
single file format) is not the best way to tackle the problem and more
thorough checks are needed, also to detect edge cases.

This is why BANG tries to do a lot more work and focus on correctness of
data that is unpacked by parsing and verifying contents (and still then it
gets it sometimes wrong).

## Framework

Conceptually BANG is divided into two parts:

1. an unpacking program that recursively unpacks files
2. a set of analysis programs that are run on result of the unpacking process

with an additional set of tools to create data sources that are used by
the analysis programs.

The unpacking program consists of a scan queue from which threads pick tasks
and a set of parsers for various file formats that can parse formats and
extract contents.

A scanning task is a set of metadata, including a reference to a file. The file
from the task is parsed by one or more parsers. Which parsers are run is based
on various features, such as known signatures ("magic" headers which many file
formats have) or known extensions in case there isn't a known signature, but
there is a known extension (example: Android sparse data files).

If any files are extracted from a file during the scanning process, a new
scanning task is created for each of the unpacked files and the tasks are
inserted into the queue to be scanned. This continues until there are no files
left to scan.

For each file that is scanned in this process the metadata is stored in a
separate directory in a Python pickle. Metadata contains information such as
names, hashes, unpacked files, and so on, but can also include extracted data
such as function names, graphics metadata, etcetera.

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

1. check if the file is a regular file, or if it is a special file, like
   a block or character device, a socket file, or if it is a directory.
   Only regular files are scanned.
2. analyze the file to verify what kind of file it is, and if any data
   can be extracted from it in case it is a container format (file system,
   archive, compresed file, etcetera), or if it is a regular file with data
   appended to it, or prepended in front of it.
3. compute various checksums (MD5, SHA1, SHA256, optionally TLSH for certain
   files and telfhash for ELF files)

This is done in a so called *pipe line* (see below), which concatenates the
different kinds of parsers.

Many file types have a certain header that indicates the file type. On Linux
systems these file types are typically described in a file type database like
`/usr/share/magic`. Examples would be gzip, or GIF.

This is not true for every file. For these files other information has to be
used, such as a known extension (quite popular on for example Android and other
Google products). In other cases a parser just needs to be run to see if a
file can be unpacked in a trial and error way. Sometimes the parser can be
determined from the unpacking context.

To determine which parser should be run the following steps are taken:

1. see if one or more parsers were suggested by the previous unpacker: there
   is a mechanism to give hints to the unpacker to select the correct parser.
   This is useful if the file can only be one kind of file, but there are
   overlapping signatures or there are no features that would normally be used
   to determine the file type. The suggested parsers can be propagated by
   passing them in the meta directory as `suggested_parsers`. An example of a
   parser doing this is the ELF parser that uses it for any unpacked `.BTF`
   and `.BTF.ext` sections.
2. check for a known extension. This is for files that always have the same
   extension, but that have no known magic header. Examples are Android sparse
   data image formats (for example "protobuf" files), or several other Android
   or Google formats (Chrome PAK, etc.)
3. search for known magic headers for a file, after which several checks are
   run and data is possibly carved from a larger file. Most parsers are in this
   category. Good examples are the PNG and GIF parsers.
4. run leftover parsers for so called "featureless files", where it is not
   immediately clear what is inside and the parser is basically just trying
   to see if it can get lucky. An example is the `base64` parser, which has no
   known extension and no magic header.

The files are scanned in the above order to prevent false positives as much
as possible. Sometimes extra information will be passed downstream to make a
better guess.

The UnpackParser class is the base class for recognizing, analyzing and
unpacking files. It has methods to parse, to write information to a meta
directory, and to unpack to a meta directory.

#### Meta directories

The analysis for each file will record metadata, extracted files (if the file
consists of multiple concatenated files), and unpacked files (in case the file
contains files itself). All this information is stored in a *meta directory*.

The top meta directory is called `root`, and every extracted or unpacked file
will have its own meta directory with its own unique name. The meta directory
will not contain the file, but refers to it by storing the pathname in the meta
directory's `pathname` file. The meta directory's `info.pkl` file contains a
data structure that maps extracted and unpacked paths to other meta
directories. It also contains general metadata and unpacked symlinks.

Unpacked files that have absolute paths can be found under `abs`, while those
with relative paths are under `rel`. Files that are carved from a larger file
are stored in a directory `extracted`. Files like boot blocks (example: ISO9660
file systems) are stored in the directory `block`.

This structure makes it harder to navigate unpacked results, but unpacked files
will not clutter the directory structure. To navigate the results there are
tools, see the file `showing-results.md` for more information.

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
  file object to the parsers.
* Pre-parsing checks: UnpackParsers can implement quick heuristic checks before
  doing large parses.

### Reducing I/O with buffers and memoryviews

For some unpackers it has been attempted to reduce memory usage using
techniques described in this blog post:

<https://eli.thegreenplace.net/2011/11/28/less-copies-in-python-with-the-buffer-protocol-and-memoryviews>

As this method only works well if data is copied around a lot (which isn't
happening anymore in BANG) it is not used a lot.

### Prevent copying data to user space by using `os.sendfile()`

One technique that is used is to copy data from and to files (for example:
temporary files) without copying the data to user space first, but letting
the kernel copy it directly is using `os.sendfile()`. This system call
instructs the kernel to do an "in kernel" copying.

This might be replaced in the future by `os.copy_file_range()`.
