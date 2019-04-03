# Defensive publications about BANG

The following defensive publications were written about (upcoming) functionality in BANG:

## Recognizing a natural language or language class in source code files

When doing analysis of source code archives from an unknown origin it can be
helpful to find out where the code originated from geographically. Comments in
these files can be helpful, as they are quite often written in the native
natural language of the developer. Finding out which language the file is in
can help understanding the flow of the code (example: translating comments) and
provenance.

By analyzing the contents of a file and seeing which character sets the contents
belong to a better guess can be made.

https://www.tdcommons.org/dpubs_series/1898/

## Using build identifiers to fingerprint ELF binaries and link to build information without having access to source code

Finding out where a software program or library comes from and how it was built
without having direct access to the source code is not a trivial problem to
solve. While versions of programs can be fairly accurately guessed this is a
lot more difficult for build configuration. By comparing build identifiers from
binaries of which nothing is known with build identifiers extracted from
binaries for which source code and build information is available it is in
certain cases possible to find out what source code and build information was
used for a binary.

https://www.tdcommons.org/dpubs_series/1897/

## Better unpacking binary files using contextual information

To unpack firmware files, disk images, raw flash dumps, file systems or other
archives various tools are available, that examine the contents of the file,
find offsets of archives, compressed files, media files and so on, carve these
from a larger file, decompress the carved files, and make the unpacked data
available for recursive unpacking. Currently available tools treat all found
files of a certain type the same (all PNG files are treated the same, all ZIP
files are treated the same and so on), without taking the context in which
they were found into account, which actually could matter depending on the
situation. This document describes possible approaches to this problem, where
contextual information from unpacking is made available to allow for more
accurate unpacking and labeling of files.

https://www.tdcommons.org/dpubs_series/1919/
