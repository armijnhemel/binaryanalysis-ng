# Writing a parser

To support a new format it is necessary to write a parser that needs to be able
to do the following:

1. parse
2. calculate the size
3. unpack
4. determine labels and metadata

A new parser derives from the `UnpackParser` class. To implement functionality
different methods need to be redefined.

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

## `parse()`

The main parsing method is called `parse()`. This method is used to parse and
verify if the contents of the data that is being parsed is correct. All of the
sanity checks should be done here and not later in the unpacking phase. Ideally
nothing should be written to disk in this phase, although this isn't always
possible.

Notes: `self.offset` is still relevant when:

1. using `sendfile()`
2. when checking if the file scanned is the whole file

## Common mistakes

Below are a few common mistakes (well, mistakes that *we* made in the past) and
their solutions.

### Forgotten `__init__.py` files

The parsers won't be picked up if there isn't a `__init__.py` file in the
directory as well as in every parent directory.
