# Process ELF binaries with cve-bin-tool

`cve-bin-tool` (<https://github.com/intel/cve-bin-tool>) is a tool to search
for known CVEs in a small subset of frequently used open source packages such
as `libpng`, `busybox`, `openssl`, and so on.

It downloads a CVE database and checks packages for known vulnerabilities and
then outputs these in a variety of formats.

## cve-bin-tool in BANG

The program in this directory is a proof of concept to see how `cve-bin-tool`
can work in conjunction with BANG. This script is expected to run repeatedly
to report on newly found vulnerabilities.

## TODO

Things that need to be figured out in a wider context (not this script):

* storing results
* retrieving earlier stored results
