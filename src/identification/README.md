# Identify ELF binaries with YARA, VulnerableCode and proximity matching

This directory contains various scripts and associated files for identifying
binaries using a few methods namely YARA, VulnerableCode and proximity
matching.

[YARA][yara] is a tool to match patterns in files with rules.
[VulnerableCode][vulnerablecode] is an open source vulnerability database. The
[Proximity Matcher webservice][proximity_matcher] is a webservice to quickly
find a closest match of a TLSH hash in a set of known TLSH hashes, which can
then be correlated to known files.

The scripts are proof of concept files that show how the individual methods
can be used. Work is underwah to create is one script that combines multiple
methods into a single workflow.

The "all in one" script is `bang_identification.py` and it combines YARA,
proximity matching and VulnerableCode.

## YARA in BANG

The file `bang_identification_yara.py` is a proof of concept to see how YARA
can work in conjunction with BANG. Currently it only works with ELF binaries.

Rules for YARA can be generated (from either binaries or source code) using
the scripts in the `maintenance/yara` directory. The rules can then be run
on binaries directory or on data extracted from binaries.

The script processes results from BANG, searches for ELF files in the results,
grabs any extracted identifiers (strings, function names, variable names),
concatenates these identifiers (one per line) and lets YARA run rules on the
concatenated results.

The extraction and concatenation parts are option: running YARA on the binary
directly would also work, but there might be some false positives. By weeding
out unwanted data first false positives are reduced.

## VulnerableCode in BANG

Data in VulnerableCode can be accessed via a Web API. Code that wraps around
this API can be found in the file `VulnerableCodeConnector.py`. Configuration
(endpoint, user name, password, etc.) is done in the configuration file.

The parameter to a query should be a valid Package URL. The output is the raw
output from VulnerableCode that a script should process further. A small demo
can be found in the file `vulnerabletest.py`.

# Putting it all together

The script `bang_identification.py` combines several methods.

# References

[yara]:https://virustotal.github.io/yara/
[vulnerablecode]:https://github.com/nexB/vulnerablecode
[proximity_matcher]:https://github.com/armijnhemel/proximity_matcher_webservice/
