# YARA rule generation scripts

This directory contains scripts to generate YARA rules. There are two scripts

1. script to generate YARA rules from source code
2. script to generate YARA rules from BANG results

## Source code processor (TODO)

The script takes source code archives, unpacks them, extracts data using
`ctags` and `xgettext` and generates YARA rules from them.

## Binary

The script takes result files of BANG scans (for example: Debian archive
files) and creates YARA files. Optionally it can use a list of low quality
identifiers that can be filtered to make the YARA rules simpler.

## Generating a list of low quality identifiers

There are several identifiers such as function names and variable names
that can be found in many binaries and that have generic names. Although
they can still be useful they can also lead to false positives if there are
only generic names. They also take up unnecessary space as YARA has a maximum
number of rules (10,000).

Examples are:

* very short identifiers (a single character)
* identifiers that are a substring of other identifiers as these could lead to
false positives in YARA
* identifiers that occur in many packages. A good example: weak ELF symbols
<https://en.wikipedia.org/wiki/Weak_symbol>

A prefab list of low quality identifiers can be found in the files
`low_quality_funcs` and `low_quality_vars`. These were handcrafted by looking
at all identifiers found in all ELF files in Debian 11.
