# Identify ELF binaries with YARA and Meilisearch

YARA (<https://virustotal.github.io/yara/>) is a tool to match patterns in
files to rules. Meilisearch (<https://www.meilisearch.com/>) is a search
engine.

## YARA in BANG

The program in this directory is a proof of concept to see how YARA can work
in conjunction with BANG. Currently it only works with ELF binaries.

Rules for YARA can be generated (from either binaries or source code) using
the scripts in the `maintenance/yara` directory. The rules can then be run
on binaries.

The script `bang_identification_yara.py` processes results from BANG, searches
for ELF files in the results, grabs any extracted identifiers (strings, function
names, variable names), concatenates these identifiers (one per line) and lets
YARA run rules on the concatenated results.

The extraction and concatenation parts are option: running YARA on the binary
directly would also work, but there might be some false positives. By weeding
out unwanted data first false positives are reduced.

## Meilisearch in BANG

The program in this directory is a proof of concept to see how Meilisearch can
work in conjunction with BANG. Currently it only works with ELF binaries.

A database for Meilisearch can be populated (from source code) using the
scripts in the `maintenance/meilisearch` directory. This database can then be
queried when analyzing results obtained with BANG.

The Meilisearch database script currently only extracts function names and
variable names to put into Meilisearch.
