CURRENTLY BROKEN

The `src/elf` directory has scripts to create linking graphs for ELF files as
unpacked by BANG. For background information either skip to the end of this
file or read:

<https://lwn.net/Articles/548216/>

# Background

On Unix(-like) systems such as Linux executables are typicaly in the ELF
executable format. On most systems the executables are dynamically linked,
meaning that dependencies are only resolved and loaded at run time, instead
of at build time. Some open source licenses explicitly mention dynamic linking
(for example LGPL 2.1, section 6b) which makes it important to know which
files link with each other.

Looking at a single ELF file is therefore not enough. Even looking at the
direct dependencies is not sufficient but the whole linking graph has to be
looked at to find out what the (likely) run time dependencies are.

ELF files record several bits of useful information:

1. a list of symbols (function names, variable names) that are needed at
runtime
2. a list of symbols (function names, variable names) that are exported/made
available (for example: libraries)
3. a list of file names of other ELF files (or symbolic links to other ELF
files) in which the symbols that are needed can possibly be found

During run time the so called "dynamic linker" sees if the ELF files from
step 3 can be found in its search path. If so it extracts the symbols from
these files (step 2) and matches them with the symbols from step 1. It is
possible to have two libraries with the same name but in different paths. Which
library is chosen depends on the configuration of the dynamic linker and the
order in which the libraries are searched.

There are ways to "tighten" the connections between ELF files and their
dependencies. One method is to hardcode the path to a specific ELF file using
either `RPATH`, or `RUNPATH` which makes it possible to somewhat limit from
which libraries symbols are chosen.

Another way is to use symbol versioning information: some ELF files require
that symbols from a specific version of a library are used. Some libraries,
for example `glibc`, contain version information. If a special version of the
symbol is recorded (in a library) or needed (by another ELF file using the
library), then the version information needed for that symbol is recorded in
special ELF sections with version information, that have the types `VERSYM`
and `VERNEED`, as can be seen when running `readelf` on a binary:

```
$ readelf -WS /bin/ls
There are 32 section headers, starting at offset 0x23fe0:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
....
  [ 9] .gnu.version      VERSYM          000000000000173c 00173c 000108 02   A  7   0  2
  [10] .gnu.version_r    VERNEED         0000000000001848 001848 0000e0 00   A  8   2  8
```

The `readelf` program displays versioning information in the symbol table using
a `@` character:

```
$ readelf -Ws /bin/ls | grep @ | head -n 2
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ctype_toupper_loc@GLIBC_2.3 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)
```

The scripts made for BANG do something similar to the dynamic linker, but
instead of running the program graphs are created for displaying and searching.

# Creating linking graphs

The scripts can output in several formats. Currently supported:

* Cypher (Neo4J)
* dot (graphviz), output in PNG and SVG

This script originally comes from the following repository:

<https://github.com/armijnhemel/compliance-scripts/>

and was adapted to work with output from BANG.

# Software requirements

* Neo4J (tested with 3.4.9 community edition) to load the resulting Cypher files
* python3-pydot

These can be (partially) installed by running:

```
$ nix-shell analysis.nix
```

in the top level directory.

# License

Licensed under the terms of the General Public License version 3

SPDX-License-Identifier: GPL-3.0-only

Copyright 2018-2026 - Armijn Hemel

# Usage

1. unpack a root file system of a firmware into a directory (example: /tmp/rootfs)
2. run the script with the right parameters for output format and output directory

This script can be used to generate graphs after unpacking a firmware with
BANG as follows:

    $ python3 generate_elf_graph.py -d /path/to/bang/result/directory -f format -o /path/to/output/directory

for example:

    $ python3 generate_elf_graph.py -d ~/tmp/bang-scan-gpiy5nb2/ -f cypher -o /tmp/cypher

which creates a graph in Cypher format.

To generate PNG and SVG files using Dot/graphviz supply the parameter `-f dot`:

    $ python3 generate_elf_graph.py -c /path/to/config -d /path/to/bang/result/directory -f dot -o /path/to/output/directory

for example:

    $ python3 generate_elf_graph.py -d ~/tmp/bang-scan-gpiy5nb2/ -f dot -o /tmp/dot

# Challenges and shortcomings

There are a few shortcomings when using this tool. First of all, it is
restricted by file system and archive boundaries. Even though on a system
files could be in different file systems that are mounted during run time
(using different squashfs file systems has been observed, for example in Ubuntu
snaps) it is currently not possible to properly reconstruct these mount points
from the binary, so the scope is limited to single file systems or archives.

# Loading graphs into Neo4J 

To load and query the graphs in Neo4J some extra steps have to be taken.

## Getting Neo4J

Get the community edition at:

<https://neo4j.com/download-center/>

Since Neo4J tends to shuffle these download links around every once in a while
they might not be accurate.

Then load the Cypher file into Neo4J (figure 1) and after it has finished
loading (figure 2) run the loaded graph by "playing" the script. This should
load all the data into the database and nodes and edges should show up in
the database overview (figure 3). Clicking on "ELF" should show a number
of nodes of the type "ELF" (figure 4).

It might be that Neo4J displays an error saying that there is a
`StackOverflowError` and suggests to increase the size of the stack. As there
will likely be quite a few nodes and edges it is advised to increase the stack
a bit more than the suggested 2M, and set it to 200M or so:

    dbms.jvm.additional=-Xss200M

By default only 25 nodes are shown, using this query:

    MATCH (n:ELF) RETURN n LIMIT 25

To change this to show for example all nodes use this query instead:

    MATCH (n:ELF) RETURN n

To select just one node (for example: /bin/busybox):

    MATCH (n) WHERE n.name='/bin/busybox' RETURN n

To select all nodes where there is a relation "LINKSWITH":

    MATCH n=()-[:LINKSWITH]-() return n

To select a single node and everything that it links with (figure 5):

    MATCH n=({name:'/bin/busybox'})-[:LINKSWITH]-() return n

To select all files that link with a certain library (figure 6):

    MATCH n=()-[:LINKSWITH]-({name: '/lib/libixml.so'}) return n
