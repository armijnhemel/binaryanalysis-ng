# YARA rule generation scripts

This directory contains scripts to generate YARA rules. There are two scripts

1. script to generate YARA rules from source code
2. script to generate YARA rules from BANG results

## Source code processor (TODO)

The script takes source code archives, unpacks them, extracts data using
`ctags` and `xgettext` and generates YARA rules from them.

## Binary processor

The script takes result files of BANG scans (for example: Debian archive
files) and creates YARA files. Optionally it can use a list of low quality
identifiers that can be filtered to make the YARA rules simpler.

### Running BANG to extract identifiers

First you need to run BANG on a collection of files, for example all `.debs`
from Debian. It is recommended to use the following configuration options:

    removescandata = yes
    logging = no

These options will remove the scan output and prevents large log files to
be written as they will not be used by the YARA rule generator script.

Then run the script to generate the YARA files. The script has two mandatory
arguments: a configuration file (in YAML format) and the directory with BANG
scan results. An exanple configuration file `yara-config.yaml` is provided
in this directory and should be adapted to your local settings.

An example invocation could look like this:

    $ python3 yara_from_bang.py -c yara-config.yaml -r ~/tmp/debian

There are some settings in the configuration that determine which identifiers
will be written to the YARA files. These are described in the sample
configuration file.

It is possible to filter low quality identifiers (described later). These
should be passed to the script in Python pickle format:

    $ python3 yara_from_bang.py -c yara-config.yaml -r ~/tmp/debian -i low_quality_identifiers.pickle

### Low quality identifiers

There are several identifiers such as function names and variable names
that can be found in many binaries and that have generic names. Although
they can still be useful they can also lead to false positives if there are
only generic names. They also take up unnecessary space as YARA has a default
maximum number of rules (10,000).

Examples are:

* very short identifiers (a single character)
* identifiers that are a substring of other identifiers as these could lead to
false positives in YARA
* identifiers that occur in many packages. A good example: weak ELF symbols
<https://en.wikipedia.org/wiki/Weak_symbol>

A prefab list of low quality ELF identifiers can be found in the files
`low_quality_elf_funcs` and `low_quality_elf_vars`. These were handcrafted by looking
at all identifiers found in all ELF files in Debian 11.
