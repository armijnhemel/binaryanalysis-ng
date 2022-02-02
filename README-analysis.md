# Running the BANG analysis scripts

BANG is conceptually split into three parts:

1. firmware unpacker
2. knowledgebase maintenance scripts
3. analysis scripts

This README covers the analysis scripts.

The analysis scripts work on the results of the firmware unpacker and
(optionally) use data from the knowledgebase generated with the maintenance
scripts.

Currently there are the following analysis scripts as "proof of concept":

* apk\_identifier
* cve\_finder
* nsrl\_lookup

## apk\_identifier

The script, configuration and more information can be found in the directory
`apk_identifier`.

This script searches the BANG results for any APK (Android packages) and runs
`apkid` on every APK that is found. For this the script needs access to the
original scan data.

## cve\_finder

The script, configuration and more information can be found in the directory
`cve`.

This script searches the BANG results and runs `cve-bin-tool` on every ELF
file that was detected.

## nsrl\_lookup

The script, configuration and more information can be found in the directory
`nsrl`.

This script searches the BANG results and runs a query on the NSRL database
for every file that is found.
