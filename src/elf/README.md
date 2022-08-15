This directory has scripts to create linking graphs for ELF files as unpacked
by BANG. For background information either skip to the end of this file or
read:

<https://lwn.net/Articles/548216/>

The scripts can output in several formats. Currently supported:

* Cypher (Neo4J) (default, this might change)
* dot (graphviz), output in PNG and SVG

This script originally comes from the following repository:

<https://github.com/armijnhemel/compliance-scripts/>

and was adapted to work with output from BANG.

# Software requirements

* Neo4J (tested with 3.4.9 community edition) to load the resulting Cypher files
* python3-pydot

# License

Licensed under the terms of the Affero General Public License version 3

SPDX-License-Identifier: AGPL-3.0-only

Copyright 2018-2022 - Armijn Hemel

# Usage

1. unpack a root file system of a firmware into a directory (example: /tmp/rootfs)
2. adapt the configuration file to change the directory where Cypher files will be stored
3. run the script

This script can be used to generate graphs after unpacking a firmware with
BANG as follows:

    $ python3 generate_elf_graph.py -c /path/to/config -d /path/to/bang/result/directory -r root/in/firmware

for example:

    $ python3 generate_elf_graph.py -c graph.config -d ~/tmp/bang-scan-gpiy5nb2/ -r TEW-636APB-1002.bin-0x00150000-squashfs-1

which creates a graph in Cypher format.

To generate PNG and SVG files using Dot/graphviz supply the extra parameter
`-o dot`:

    $ python3 generate_elf_graph.py -c /path/to/config -d /path/to/bang/result/directory -o dot -r root/in/firmware

for example:

    $ python3 generate_elf_graph.py -c graph.config -d ~/tmp/bang-scan-gpiy5nb2/ -o dot -r TEW-636APB-1002.bin-0x00150000-squashfs-1

# Loading graphs into Neo4J 

To load and query the graphs in Neo4J some extra steps have to be taken.

## Getting Neo4J

Get the community edition at:

https://neo4j.com/download-center/

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

# Background

On Unix(-like) systems such as Linux executables are typicaly in the ELF
executable format. On most systems the executables are dynamically linked,
meaning that dependencies are only resolved and loaded at run time, instead
of at build time. Some open source licenses explicitly mention dynamic linking
(for example LGPL 2.1, section 6b) which makes it important to know which
files link with eachother.

Looking at a single file is therefore not enough. Even looking at the direct
dependencies is not sufficient but the whole linking graph has to be looked
at to find out what the (likely) run time dependencies are.

ELF files record several bits of useful information:

1. a list of symbols (function names, variable names) that are needed at
runtime
2. a list of symbols (function names, variable names) that are exported/made
available
3. a list of file names of other ELF files (or symbolic links to other ELF
files) in which the symbols can possibly be found

During run time the so called "dynamic linker" sees if the ELF files from
step 3 can be found in its search path. If so it extracts the symbols from
these files (step 2) and matches them with the symbols from step 1. It is
possible to have two libraries with the same name but in different paths. Which
library is chosen depends on the configuration of the dynamic linker and the
order in which the libraries are searched.

Sometimes some search paths are hardcoded to a specific ELF file using the
either `RPATH`, or `RUNPATH` which makes it possible to somewhat limit from
which libraries symbols are chosen.

The scripts here do something similar to the dynamic linker, but instead of
running the program graphs are created for displaying and searching.
