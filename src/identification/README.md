# Identify ELF binaries with YARA, Meilisearch, VulnerableCode and proximity matching

YARA[1] is a tool to match patterns in files to rules. Meilisearch[2] is a
search engine. VulnerableCode[3] is an open source vulnerability database.
The Proximity Matcher webservice[4] is a webservice to quickly find a closest
match of a TLSH hash in a set of known TLSH hashes, which can then be
correlated to known files.

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

The Meilisearch database script extracts strings, function names and variable
names to put into Meilisearch. The search script only uses the strings.

This method is very noisy due to how Meilisearch works, so it is not
recommended to use except as a last resort.

## VulnerableCode in BANG

Data in VulnerableCode can be accessed via a Web API. Code that wraps around
this API can be found in the file `VulnerableCodeConnector.py`. Configuration
(endpoint, user name, password, etc.) is done in the configuration file.

The parameter to a query should be a valid Package URL. The output is the raw
output from VulnerableCode that a script should process further. A small demo
can be found in the file `vulnerabletest.py`.

# References

[1] <https://virustotal.github.io/yara/>
[2] <https://www.meilisearch.com/>
[3] <https://github.com/nexB/vulnerablecode>
[4] <https://github.com/armijnhemel/proximity_matcher_webservice/>
