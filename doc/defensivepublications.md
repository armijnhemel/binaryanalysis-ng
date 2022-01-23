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

<https://www.tdcommons.org/dpubs_series/1898/>

## Using build identifiers to fingerprint ELF binaries and link to build information without having access to source code

Finding out where a software program or library comes from and how it was built
without having direct access to the source code is not a trivial problem to
solve. While versions of programs can be fairly accurately guessed this is a
lot more difficult for build configuration. By comparing build identifiers from
binaries of which nothing is known with build identifiers extracted from
binaries for which source code and build information is available it is in
certain cases possible to find out what source code and build information was
used for a binary.

<https://www.tdcommons.org/dpubs_series/1897/>

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

<https://www.tdcommons.org/dpubs_series/1919/>

## Finding (partial) code clones at method level in Android programs without access to source code to detect copyright infringements or security issues

Nearly all programs for Android devices are distributed without source code
being made available. This means that it is a lot harder to do audits of these
programs for for example copyright infringement detection or security issue
detection. By examining individual methods inside an Android program and
comparing these to a database of methods from known programs it is possible to
make an educated guess of which programs or program fragments are used in the
program, and possibly detect copyright infringements or trojaned versions
of programs.

<https://www.tdcommons.org/dpubs_series/2479/>

## Finding (partial) code clones at method level in binary Java programs without access to source code to detect copyright infringements or security issues

Many Java programs are distributed in binary form without source code being
made available. This means that it is a lot harder to do audits of these
programs for for example copyright infringement detection or security issue
detection. By examining individual class files inside a Java program and
comparing these to a database of class files from known programs it is possible
to make an educated guess of which programs or program fragments are used in
the program, and possibly detect copyright infringements or trojaned versions
of programs.

<https://www.tdcommons.org/dpubs_series/3658/>

## Finding out how close source code files are to files in the Git version control system.

A lot of popular software is developed using a version control system.
Historically systems such as RCS, CVS and Subversion were used, but a lot of
developers have moved to Git. These systems have a lot of information available
about the history of a file. When software is distributed, it is often
distributed without this history information. In some situations it is
important to find out how close a certain piece of software is to any
given version in a version control system, for example for assessing
copyright, security research or other provenance issues.

<https://www.tdcommons.org/dpubs_series/3925/>

## Computing a distance between a source code directory and another source code directory

Sometimes it is important to see how much a vendor's source code tree is
deviating from an upstream open source project such as the Linux kernel,
as big deviations potentially mean increased maintenance costs, as
changes/fixes might need to be backported from the official version. In this
document a method to compute a score to quantify possible maintenance costs
is proposed.

<https://www.tdcommons.org/dpubs_series/3942/>

## Using ELF symbols extracted from dynamically linked ELF binaries for fingerprinting

Detecting provenance of dynamically linked ELF binaries can be achieved by
creating fingerprints using information in the dynamic symbol table and
comparing these to fingerprints created by symbols from reference binaries,
or from symbols extracted from source code. Fingerprints can be stored in a
database or turned into rules for the YARA pattern matching tool.

<https://www.tdcommons.org/dpubs_series/4441/>

## Open source license text matching and reporting

When using open source software it is important to find out under which open
source license the software was released under, as this determines what can
and cannot be done with the software. There are many open source software
licenses with different license terms that are not always compatible with each
other. Different pieces of software released under incompatible software
licenses cannot be combined with each other. It is therefore necessary to find
out which licenses are declared in source code and correctly report these.
Source code repositories or releases that are open source licensed almost
always contain a text file with the text of the license that the code has been
released under, such as the GNU General Public License (various versions), the
Apache License (various versions), and so on. While open source license texts
are meant to be immutable, they are frequently changed. Many times the changes
are purely cosmetic, but sometimes the license are changed in such a way that
the changes could affect the meaning of the license. It is important to be able
to detect such changes. In this article a very lightweight method for comparing
license texts found in source code archives with official license texts is
presented.

<https://www.tdcommons.org/dpubs_series/4769/>

## Finding version information for binary files with YARA fingerprinting using a multi-layered approach

Detecting provenance of binary files can be done by using the YARA pattern
matching tool. It is easy to write or generate YARA rules to detect a
particular version of a binary file, but detection can be time consuming as
for some packages there are many versions, meaning there are potentially lots
of different rules that need to be applied, with most of them applied while it
is already clear that there will never be any successful matches for those
rules. Using multiple scan phases allows doing a coarse check first to
determine the overall package using a generic package rule and then zooming
in to find the particular version using package/version specific rules.

<https://www.tdcommons.org/dpubs_series/4818/>
