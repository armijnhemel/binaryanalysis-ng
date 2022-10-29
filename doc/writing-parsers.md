# Writing a parser

To support a new format it is necessary to write a parser that needs to be able
to do the following:

1. parse
2. calculate the size
3. unpack
4. determine labels and metadata

A new parser derives from the `UnpackParser` class. To implement functionality
different methods need to be redefined.

## First: an important word about offsets

To make it easier for the parsers the file that is presented to the parser and
unpacker is not the real file. Instead, it has been wrapped in a so called
`OffsetInputFile` wrapper, that takes care of offsets. This is so the parser
does not need to worry too much about where in the file it actually is reading
and what offsets need to be taken care off (which is always a source of bugs).
This makes the parser easier and cleaner, as it always seems as if the parser
starts at offset `0`. When using Kaitai Struct based parsers this usually does
not matter at all (unless the Kaitai Struct specification uses file size
checks, which some unfortunately do) as tKaitai Struct will read from a stream
of bytes and all that is needed is that the file pointer is pointing at the
right offset.

The offset of the signature in the *original* file can still be accessed
through `self.offset`. The original file can be accessed (if needed) via
`self.infile.infile`. In an ideal case these are never needed, but there are
exceptions, for example when using external tools, or when writing data in
bulk using `sendfile()`.

There are various modules that are using `sendfile()`, for example:

1. `AndroidDtoUnpacker`
2. `AndroidMsmBoot`

and also parsers that are using external tools, such as:

1.

## `extensions` and `signatures`

The two data structures `extensions` and `signatures` are defined that define
which class of parsers are run. They are independent from each other.

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

When deciding if `extensions` or `signatures` should be used the rule of thumb
is that if there is a signature, then `signatures` should be used and
`extensions` should not be used. If there is no signature but there is a
reliable extension, then `extensions` should be used.

## `pretty_name`

The `pretty_name` string should be set to something that describes the file
format, for example `jffs2` (for JFFS2 file systems) or `elf` (for ELF
binaries). This is mostly used for identification, so it is highly recommended
to give it a unique name.

## `__init__()`

This method normally does not need to be redefined, except in some cases where
more contextual information is needed. An example is `base64`, where there is a
check to see if the file was unpacked from a Chrome PAK file to avoid needless
false positives.

Another example is `CbfsUnpackParser` because there the wrapped file should
not be used.

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
in any of the other methods.

## `unpack()`

## `calculate_unpacked_size()`

By default the unpacked size is set to wherever the file pointer is at in the
wrapped input file (so the offset is taken care of). This is not always the
correct size. For example, when a Kaitai Struct based parser using `instances`
is used (and there are many) some of the data structures are actually Python
`properties` and these are not automatically parsed and thus the file pointer
is not moved.

Frequently the size is set during parsing by `parse()` (example:
`AllwinnerUnpackParser`) and `calculate_unpacked_size()` should not do anything
and can be set to:

```
def calculate_unpacked_size(self):
    pass
```

## `labels` and `metadata`

The two properties `labels` and `metadata` are used to set labels and metadata
respercively. What goes where is sometimes a bit arbitrary (or at least has
been in the past) but as a rule of thumb: `labels` should be as small as
possible while in `metadata` everything deemed interesting about a file should
go. For example: `uid` and `gid` information per file for an archive or file
system should go into `metadata`. Identifiers extracted from executables and
architecture information should go into `metadata`. Information that something
is a file system or archive should go into `labels`.

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
