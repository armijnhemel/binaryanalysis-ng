# Various bits of data

This directory contains various bits of data, including:

1. a list of files/checksums of files that should not be unpacked or scanned

## Files that should not be unpacked or scanned

There are various known files that should not be unpacked or scanned. Examples
include:

1. test data with known broken or problematic data, like `gnu-sparse-big.tar`,
   a test `tar` file of 5120 bytes that unpacks to a 60 GB sparse file. BANG
   does not recognize sparse files (yet) and so will try to scan the 60 GB
   file which will take a lot of time.
