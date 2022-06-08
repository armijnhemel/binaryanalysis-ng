# Proximity matching

Proximity matching is a way to quickly find a closest match of a TLSH hash in
a set of known TLSH matches, which in turn correspond with files.

Proximity matching can be done with a special data structure called "Vantage
Point Trees", for example using a webservice[1].

## Generating JSON data files from BANG results

The first step is to process BANG results and extract the right information
fromn the results and, if necessary, compute more results. Currently ELF files
and Android Dex files can be processed. By default ELF files are processed
while Android Dex files are not. This can be changed in the configuration
file.

The script to extract this information writes this information to JSON files.
The name of the file is a SHA256, with the extension `.json`. For ELF files
the SHA256 of the original file is used, for Android Dex bytecode it is the
SHA256 of the bytecode of each method.

These files are stored in a separate directory (of which the parent is
configurable in the configuration file). For ELF files the result is stored in
a directory named `elf`. For Android Dex bytecode (per method) the directory
is called `dex`.

```console
$ python3 proximity_hash_from_bang.py -c proximity-config.yaml -r /path/to/bang/result/directory
```

Optionally there is the `-f` flag to force to overwrite previous results. This
should be used in case any of the parameters in the configuration file are
changed.

### ELF

Currently the following TLSH results are extracted:

* TLSH of the entire file (if present)
* telfhash import hash (if present)

and the following hash is computed:

* TLSH for identifiers extracted from ELF files (strings, function names and
variable names, in that order, possibly cleaned up to remove low quality
identifiers). The identifiers are cleaned up (depending on settings, see
later), sorted per type (first strings, then function names, then variable
names) and concatenated (one space between each identifier).

#### Configuration of TLSH identifier hash computation

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

### Android Dex

For Dex files the TLSH computed for the bytecode of each individual method is
extracted from the BANG results and written to a file. Currently methods are
not yet filtered, but this might change in the future to be able to ignore
certain methods (for example: `<init>` and `<clinit>`) that are inserted by
the compiler.

It should be noted that when processing a large number of Dex files there will
be hashes for many methods (at least a few hundred per Dex file). This is why
scanning Dex methods is not enabled by default.

## Extracting data from MalwareBazaar files

MalwareBazaar is a project run by abuse.ch, a research project at the Bern
University of Applied Sciences. It offers a dataset with information about
known malware under a CC0 license at: <https://bazaar.abuse.ch/export/>. This
dataset only contains information about known malware.

The standard dataset includes TLSH hashes that can easily be extracted and
turned into a Vantage Point Tree.

The script `proximity_hash_from_malwarebazaar.py` processes MalwareBazaar
CSV files and outputs JSON files with information that can be loaded into a
Vantage Point Tree object.

Note: the full dumps of the MalwareBazaar project are ZIP-files that should
first be decompressed. The incremental updates are regular CSV files.

The script to extract this information writes this information to JSON files.
The name of the file is the SHA256 recorded in the CSV file, with the extension
`.json`. These files are stored in a separate directory (of which the parent is
configurable in the configuration file). The results are stored in a directory
named `malwarebazaar`.

The script is invoked as follows:

```console
$ python3 proximity_hash_from_malwarebazaar.py -c proximity-config.yaml -m /path/to/csv
```

### Configuration of MalwareBazaar extraction

```
proximity:
    # directory to store generated JSON files
    proximity_directory: /path/to/directory/proximity
```

## Loading information JSON data files into a Vantage Point Tree object

To create the Vantage Point Tree object pickle the script
`populate_vpt_pickle.py` can be used. The script takes three parameters:

1. directory with JSON files
2. output file (where the VPT pickle will be stored)
3. name of the TLSH value that should be stored

The reason behind filtering the name is that this allows for creating different
VPT object pickles which can be loaded into different instances of the VPT web
service. The reason for this is that it doesn't make sense to mix different
TLSH values: a TLSH value for an EXE file from MalwareBazaar will never give a
close match to an identifier TLSH value calculated from an ELF file.

```console
$ python3 populate_vpt_pickle.py -j /path/to/json/files -o /path/to/output/pickle -f tlsh_filter

```
for example:

```console
$ python3 populate_vpt_pickle.py -j ~/proximity/elf/ -o /tmp/telfhash.pickle -f telfhash
```

# References

[1] <https://github.com/armijnhemel/proximity_matcher_webservice/>
