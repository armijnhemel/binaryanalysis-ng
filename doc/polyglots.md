# Processing polyglot files in BANG

There are binary blobs where it is not clear at first sight what kind of file
is contained and where it is possible that multiple unpacking paths could be
chosen. For example, it is possible to create files that are both an ext2fs
and FAT file system (<https://github.com/NieDzejkob/cursedfs>). While this
particular file system example is frivolous these so called "polyglot files"
are also used for other more nefarious uses
(<https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a>).

To allow for this kind of detection the framework needs to be adapted to
accomodate different possible unpacking paths.

## Example: bootable ISO9660

A situation where BANG cannot correctly unpack is if there is a bootable
CD-image, with an EFI boot image that is stored in the first part of the ISO.
An example is the file `FreeBSD-13.0-RELEASE-amd64-bootonly.iso` which is a
bootable CD for FreeBSD 13.

When parsing this file two possible files can be concluded:

1. EFI/MBR (offset 0x1fe)
2. ISO9660 image (offset 0x8001)

Both are correct conclusions and both files should be unpacked. It could
be argued that the ISO9660 is the "outer" file and the EFI/MBR is the
"inner" file.

## Current unpacking in BANG

At the moment only one of the two files will be unpacked. Depending on the
order in which the parsers are read it might be one or the other.

## Possible future unpacking in BANG

In the future unpacking might be done as follows:

For a particular offset all parsers that could possibly succeed are stored.
There are then two different paths ways to implement unpacking:

1. the most promising parser (that could potentially unpack the most
data) is run. If this fails then the other parsers are tried (most promising
parser first) until one succeeds.

2. all parsers are tried in parallel and results are either recombined (where
possible) or kept as separate branches of unpacking.
