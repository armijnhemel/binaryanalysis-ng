# Increasing performance of BANG

Unpacking with BANG can take a long time. There are a few tricks that you can
use to speed things up if necessary. Some of these are hardware related, others
are runtime configuration options to BANG.

## Use fast disks and lots of memory

An easy fix is to decrease disk latency by writing data to NVMe or, if
possible, a ramdisk. A ramdisk is preferred, but you need to make sure that
you don't run out of memory because for unpacking some firmware files a lot
of space can be used. For example, recent Android firmware images can easily
take 14 GiB of space or more when fully unpacked.

## Use multiple threads

By default BANG runs with 1 thread. There is the possibility to use multiple
threads, which will speed up scanning a lot. However, there is one edge case
where using multiple threads won't work and that is when a file format needs
other files to be successfully be unpacked (example: android sparse data) then
it could happen that a thread will start scanning the file before the other
files have been unpacked. BANG tries to detect this and will wait for some
seconds in case the needed file isn't found, but it could happen that the file
that is needed only becomes available after this waiting period is over.

If you are not sure, then don't use multiple threads. Otherwise: use as many
as available.

## Disable some parsers

There are a few parsers with very generic signatures that BANG will try to
unpack. These are Windows Icons (`.ico`) and TrueType fonts (`.ttf`). It
might be useful to disable these parsers in a configuration file (see
`bang-config.yaml` for an example).

Of course it depends on the types of files that are scanned, if they can
be recognized or if there is a lot of unknown data (which could lead to these
parsers being called more), and so on. A very unscientific test with a fairly
regular Linux mediaplayer firmware saw a boost in performance of about 3%.
