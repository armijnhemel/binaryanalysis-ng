# PNG file format

This document describes how BANG unpacks PNG files. Some of the information has
already been published in a blog post which you can find at:

<http://web.archive.org/web/20190325190058/http://binary-analysis.blogspot.com/2018/07/walkthrough-png-file-format.html>

The official PNG file specification can be found at:

<https://www.w3.org/Graphics/PNG/>

In the rest of this document there will be references to sections in the
official specification.

## PNG file overview

A PNG file consists of a signature, followed by a collection of chunks. Some
of these chunks are mandatory, others are optional.

The signature is followed by a set of chunks. Each chunk has 3 or 4 fields
(section 5.3 of the specification).

1. length (4 bytes) - this value is in network byte order (big endian)
1. chunk type (4 bytes)
1. chunk data (optional if length = 0)
1. CRC32 computed from chunk type and chunk data (4 bytes)

A minimal chunk (without data) is 12 bytes and a minimal PNG has three chunks:
IHDR (header), IDAT (data) and IEND (terminator).

The terminator IEND always has length 0 (meaning there is no data), the chunk
type is always IEND, so the CRC32 value is also the same. This means that the
IEND chunk is always the same 12 bytes (section 11.2.5).

The header IHDR can contain different data, but is always 25 bytes. An IDAT
chunk is minimal 12 bytes. A minimal PNG file (signature plus three mandatory
chunks) is therefore 8 + 25 + 12 + 12 = 57 bytes. A file shorter than 57 bytes
cannot be a valid PNG file.

In most cases unpacking PNG compressed data comes down to:

1. check if the file is at least 57 bytes
2. opening the file
3. reading the signature (section 5.2)
4. verifying if the first chunk is the header chunk (section 11.2.2)
5. reading and verifying chunks until the terminator chunk (section 11.2.5) is
  found, as it has to be the last (section 5.6)
6. checking if all mandatory chunks are present

# PNG file unpacking in BANG

PNG file unpacking in BANG works as follows (simplified):

1. check if the file is at least 57 bytes
2. open the file
3. read the signature (section 5.2)
4. verify if the first chunk is the header chunk (section 11.2.2)
5. verify several parameters and flags in the header chunk for which only a limited amount of values are accepted (such as "depth" or "color type")
6. verify CRC32
7. reading and verifying chunks (length, CRC32) until the terminator chunk (section 11.2.5) is found, as it has to be the last (section 5.6). Exit if the end of file is reached, or if an invalid chunk is found.
8. carve the PNG from a larger file (only if necessary, not if EOF is reached)

Chunk ordering (section 5.6) is not checked by BANG.

## Chunk names

Each chunk has a name (section 5.4). The specification defines a few standard
names, but there are also plenty of vendor specific chunks, or proposed chunk
names that were later changed. These chunk names can give additional
information about the platform a PNG came from, or was used on, such as Apple
systems, or Android devices.
