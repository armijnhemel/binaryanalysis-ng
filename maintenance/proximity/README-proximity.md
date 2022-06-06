# Proximity matching

Proximity matching is a way to quickly find a closest match of a TLSH hash in
a set of known TLSH matches, which in turn correspond with files.

## Generating JSON data files from BANG results

The first step is to process BANG results and extract the right information
fromn the results and, if necessary, compute more results.

Currently the following TLSH results are extracted:

* TLSH of the entire file (if present)
* telfhash import hash (if present)

and the following hash is computed:

* TLSH for identifiers extracted from ELF files (strings, function names and
variable names, in that order, possibly cleaned up to remove low quality
identifiers). The identifiers are cleaned up (depending on settings, see
later), sorted per type (first strings, then function names, then variable
names) and concatenated (one space between each identifier).

The script to extract this information writes this information to JSON files.
The name of the file is the SHA256 of the original file, with the extension
`.json`. These files are stored in a separate directory (of which the parent is
configurable in the configuration file). For ELF files the result is stored in
a directory named `elf`.


```console
$ python3 proximity_hash_from_bang.py -c proximity-config.yaml -r /path/to/bang/result/directory
```

Optionially there is the `-f` flag to force to overwrite previous results. This
should be used in case any of the parameters in the configuration file are
changed.

### Configuration of TLSH identifier hash computation

There are a few settings that can be used to control generation of the TLSH
identifier hash. These are found in the configuration file, although settings
are also hardcoded in the source code file.

The settings are:

```
proximity:
    # directory to store generated JSON files
    proximity_directory: /path/to/directory/proximity

    # minimal length of strings, recommended to not go below 5
    # string_min_cutoff: 8

    # maximal length of strings, recommended to not go above 200
    # string_max_cutoff: 200

    # minimal length of functions/variable names, recommended
    # to not go below 2
    # identifier_cutoff: 2

    # ignore weak ELF symbols. Recommended to set to 'true'
    ignore_weak_symbols: true
```

If any of the settings that influence how the hash is computed (all but
`proximity_directory`) are changed and the hashes are regenerated, then these
same settings should also be used for the scripts using the proximity web
service.

## Loading information JSON data files into a Vantage Point Tree object

TODO
