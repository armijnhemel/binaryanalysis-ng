# Writing a parser

To support parsing or unpacking a new format it is necessary to write code
that needs to be able to do the following:

1. parse the file
2. calculate the size of the parsed data
3. unpack the parsed data
4. determine labels and metadata

A new parser derives from the `UnpackParser` base class. To implement the
functionality mentioned above several methods need to be (possibly) redefined.

## First: an important word about offsets

To make it easier for the parsers the file that is presented to the parser and
unpacker is not the real file. Instead, it has been wrapped in a wrapper called
`OffsetInputFile` wrapper. This wrapper makes it look as if the file that is
being opened starts at offset `0`. This makes it much easier and cleaner to
write a parser and the parser does not need to worry about where in the file it
actually is reading and what offsets need to be taken care off (which has been
a source of bugs in the past).

When using Kaitai Struct based parsers this usually does not matter at all
(unless the Kaitai Struct specification uses file size checks, which some
unfortunately do) as Kaitai Struct will read from a stream of bytes and all
that is needed is that the file pointer is pointing at the right offset in the
file.

The offset of the signature in the *original* file can still be accessed
through `self.offset`. The original file can be accessed (if needed) via
`self.infile.infile`. In an ideal case these are never needed, but there are
exceptions, for example when using external tools, or when writing data in
bulk using `sendfile()` which needs to have the original offset or it will
write data in the wrong location.

There are various modules that are using `sendfile()`, for example:

1. `AndroidDtoUnpacker`
2. `AndroidMsmBoot`

and also parsers that are using external tools, such as:

1. `SevenzipUnpackParser`
2. `RzipUnpackParser`

## `extensions`, `signatures` and `priority`

The two data structures `extensions` and `signatures` are defined that define
which parser class is used. They are independent from each other.

Normally parsers rely on signatures (AKA "magic") to find the start of where
a file format starts, but not all files have a signature. For example, the
`android_sparse_data` format does not have a magic header and can only be
identified by looking at the extension of the file.

`signatures` is a list with tuples that have two elements:

1. offset of the magic signature (this does not need to be `0`!)
2. signature

An example of a signature that does not start at `0` can be found in the
`iso9660` parser. When scanning for signatures the offsets are automatically
taken into account.

Signature example:

```
signatures = [
    (32769, b'CD001')
]
```

When deciding if `extensions` or `signatures` should be used the rule of thumb
is that if there is a signature, then `signatures` should be used and
`extensions` should not be used. If there is no signature but there is a
reliable extension, then `extensions` should be used.

`priority` is used to indicate an optional priority when scanning. There
are situations when there are parser classes that match, but where one should
be preferred over the other. An example is ISO9660, where the first block
of the file system could contain anything, for example a bootblock with
an EFI bootloader. In this case the ISO9660 parser should be run,
otherwise it will be hard to extract the content (at least not until polyglot
files are supported. By default all parsers have a `priority` of `0`. To make
sure that a particular unpacker is used first the `priority` field can be set
to a higher number, for example:

```
    priority = 1000
```

## `pretty_name`

The `pretty_name` string should be set to something that describes the file
format, for example `jffs2` (for JFFS2 file systems) or `elf` (for ELF
binaries). This is mostly used for identification, so it is highly recommended
to give it a unique name.

Example:

```
pretty_name = 'iso9660'
```

## `__init__()`

This method normally does not need to be redefined, except in some cases where
more contextual information is needed. An example is `base64`, where there is a
check to see if the file was unpacked from a Chrome PAK file to avoid needless
false positives.

Another example is `CbfsUnpackParser` because for that file format the wrapped
file (using `OffsetInputFile`) should actually not be used.

## `parse()`

The main parsing method is called `parse()`. This method is used to parse and
verify if the contents of the data that is being parsed is correct. All of the
sanity checks should be done here and not later in the unpacking phase. Ideally
nothing should be written to disk in this phase, although this isn't always
possible (for example, when using external tools and data need to be carved
first because the external tools cannot work with offsets).

The goal of `parse()` is to fail as soon as possible to waste as little effort
as possible trying to find out what a file is. This means writing checks using
`check_condition()` and, if the parser uses Kaitai Struct, in the Kaitai Struct
grammar.

When using Kaitai Struct based parsers using `instances` (and there are many)
some of the data structures are actually Python `properties` which are lazily
evaluated and only parsed when requested, so the data structures have to be
explicitly walked. Some parsers where this happens are:

1. `WavUnpackParser`
2. `ElfUnpackParser`

Sometimes some data structures that are used later (by either calculating the
size or unpacking) are created during parsing and shared to avoid reparsing
in any of the other methods. Examples are all of the parsers that use `7z` for
unpacking (`ChmUnpackParser`) but also `SquashfsUnpackParser`.

## `calculate_unpacked_size()`

By default the unpacked size is set to wherever the file pointer is at in the
wrapped input file (so the offset is taken care of). This is not always the
correct size. For example, when a Kaitai Struct based parser using `instances`
is used (and there are many) some of the data structures are actually Python
`properties` and these are not automatically parsed and thus the file pointer
is not moved.

Frequently the size is set during parsing by `parse()` (example:
`AllwinnerUnpackParser`) and `calculate_unpacked_size()` should not do anything
and should be set to:

```
def calculate_unpacked_size(self):
    pass
```

This will prevent that the default `calcuate_unpacked_size()` from the
`UnpackParser` base class is run.

## `unpack()`

Unpacking files, directories, symbolic links, and so on, is done in the
`unpack()` method. One of the parameters to the `unpack()` method is a meta
directory.

The meta directory object has several convenience functions specifically for
unpacking data and hiding all kinds of implementation details, such as where
the data is written to. The meta directory takes care of this and provides a
directory where the data is written to. Depending on if the files that are
unpacked have an absolute path or a relative path these files will be written
to `abs/` and `rel/` respectively.

The result of unpacking regular files should be yielded so they can immediately
be put back into the scanning queue.

As everything has already been parsed ideally no errors should be thrown in
this method. Instead, any errors should be caught in `parse()`. That might mean
doing some double work (example: using external tools that do all kinds of
validation while unpacking), although some of the data can also be reused
(example: all of the parsers that use `7z`, such as `ChmUnpackParser`).

### Unpacking regular files

The most common operation will be writing data to a file. This can be done in
several ways, namely by reading the data first (which might already have been
done by a Kaitai Struct parser) and then writing it to the output file, or by
doing bulk writes using `os.sendfile()`.

As an example of the first, let's look at `Uf2UnpackParser`. The code for
writing the data is as follows:

```
with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
    outfile.write(self.data.uf2_block_start.data)
    for uf2_block in self.data.uf2_blocks:
        outfile.write(uf2_block.data)
    yield unpacked_md
```

The parameter `file_path` should be a valid `pathlib` object. Depending on the
format of the parsed file this is either embedded in the binary (example: files
in a file system) or can be derived from the suffix of the file (as in this
case).

The result of `unpack_regular_file()` is a tuple with another meta directory
(where the meta data of the file to be unpacked will be written), as well as an
opened file object that can be written to using `write()` (as done here) or
using `os.sendfile()`.

An example using `os.sendfile()` is `AllwinnerUnpackParser`:

```
def unpack(self, meta_directory):
    for entry in self.data.file_headers:
        file_path = pathlib.Path(entry.file_header_data.name)
        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            os.sendfile(outfile.fileno(), self.infile.fileno(), entry.file_header_data.offset + self.offset,
                             entry.file_header_data.original_length)
            yield unpacked_md
```

The name is extracted using the Kaitai Struct parser, as are the offset and
size that are needed to write the data. What should be noted is that when using
`os.sendfile()` some extra information is needed (namely the original offset)
as explained at the start of this document.

Although the meta directories in these examples are yielded immediately there
are cases where this is not easily possible. One example is the current parser
and unpacker for `ubifs`, where data of files are not in a single inode, but
scattered across the file system. Here the meta directories are stored, data
is appended to the output files and the meta directories are yielded at the end
in a single loop. Please take note: `os.sendfile()` does not work when files
are opened in append mode (this is a limitation of the underlying system call)
so cannot be used when appending to files.

### Unpacking directories

In some file formats directories are or can be stored as a separate entry.
Examples are ZIP-files, tar files, several file systems, and so on.

Unpacking directories is easy: the meta directory object has a method
`unpack_directory()` which should be called. The parameter should be a valid
`pathlib` object. No meta directory needs to be yielded.

### Unpacking symbolic links

Unpacking symbolic links is fairly straightforward. The meta directory object
that is passed has a method `unpack_symlink()` that can be called. No meta
directory needs to be yielded.

An example parser that processes symbolic links is `ZimUnpackParser`.

### Unpacking hard links

An example parser that processes symbolic links is `Jffs2UnpackParser`.

## `labels` and `metadata`

The two properties `labels` and `metadata` are used to set labels and metadata
respercively. What goes where is sometimes a bit arbitrary (or at least has
been in the past) but as a rule of thumb: `labels` should be as small as
possible while in `metadata` everything deemed interesting about a file should
go. For example: `uid` and `gid` information per file for an archive or file
system should go into `metadata`. Identifiers extracted from executables and
architecture information should go into `metadata`. Information that something
is a file system or archive should go into `labels`.

As everything has already been parsed and unpacked at this point no errors
should be thrown when setting `labels` and `metadata`.

## Common mistakes

Below are a few common mistakes (well, mistakes that *we* made in the past) and
their solutions.

### Forgotten `__init__.py` files

The parsers won't be picked up if there isn't a `__init__.py` file in the
directory as well as in every parent directory.

### Forgetting `self.offset` when using `os.sendfile()`

When writing large amounts of data using `os.sendfile()` and having a file that
does not start at `0` it is important to use `self.offset`. This is because
`os.sendfile()` operates on file descriptors. When using `OffsetInputFile` the
file descriptor of the wrapped file is the same as the original file, meaning
that parameters given to `os.sendfile()` like offsets should reflect the
situation of the original unwrapped file.
