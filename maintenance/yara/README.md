# YARA rule generation scripts

This directory contains scripts to generate YARA rules. There are two scripts

1. script to generate YARA rules from source code
2. script to generate YARA rules from BANG results

## Source code processor (TODO)

The script takes source code archives, unpacks them, extracts data using
`ctags` and `xgettext` and generates YARA rules from them.

## Binary

The script takes result files of BANG scans (for example: Debian archive
files) and creates YARA files.
