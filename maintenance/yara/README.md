# YARA rule generation scripts

This directory contains scripts to generate YARA rules. There are two
different ways to generate YARA rules:

1. from source code
2. from binaries

Generating YARA rules from binaries is currently only supported for
ELF files and Android Dex files.

## When to use which processor

There are situations where it is better to use rules generated from source
code than rules generated from binaries.

The benefit of generating rules from binaries is that you do not need to
have access to the source code to create YARA files. The drawback is that
not every binary is well suited for this, due to how the binaries are
created or processed.

Generating rules from binaries seems to work really well for the vast
majority of dynamically linked ELF binaries but not for for example
Dalvik `.dex` files.

### Dynamically linked ELF binaries

Dynamically linked ELF binaries are created from object files that are
in turned created from source code files. Dependencies (like third parties)
typically do not end up in the dynamically linked ELF file (although there
are of course exceptions, for example when there is a complete copy of
third party software included in the package), so the separation between
package and third party code tends to be clean. Information extracted from
binaries in a package usually is from just that package.

### Android Dex files

For Android Dex files it is much more difficult to make a good match using
rules generated from binaries, as Dex files are much closer to statically
linked files: you will find a lot dependencies included in the `classes.dex`
files that cannot be found in the source code of a project, but can be found
in the dependencies.

By default many programs are also obfuscated or shrunk by Android tools
such as Android Studio:

<https://developer.android.com/studio/build/shrink-code>

which advertises obfuscation of class names and method names as a feature.

This makes rules generated from binary `.dex` files not very well suited.
It is much better to create rules from source code and focus on other
identifiers, such as the strings embedded in `.dex` files.

## Source code processor

Generating YARA rules from source code involves two steps:

1. extracting identifiers from source code
2. generating YARA rules from identifiers extracted in step 1

This split is made since extracting identifiers is a fairly expensive step
(nearly all processing time is used for extracting identifiers) and is
something that typically only needs to be done once for an archive as the
data for an archive is immutable. The only reason to rerun the extraction
process is if there are errors in the extraction tools. It also allows for
incremental updates, only processing new packages.

The `bang_extract_identifiers.py` script extracts individual files from source
code archives, processes the individual files using `ctags` and `xgettext` to
get the interesting identifiers and generates JSON files with the results of
each package. These results are raw and have not been cleaned up, with the
exception of empty strings or all whitespace strings.

The extraction code script looks at the extension of the file to determine
the most likely programming language used in the source code file. Current
focus is on C/C++, Java (including Scala and Kotlin) and Javascript. Support
for more languages will be added in the future.

The script to process source code can be invoked as follows:

    $ python3 bang_extract_identifiers.py -c /path/to/config -s /path/to/sources -m /path/to/metadata

for example:

    $ python3 bang_extract_identifiers.py -c yara-config.yaml -s ~/busybox -m data/busybox.yaml

The directory with source code should contain source code archives (currently
only TAR archives are supported, support for ZIP files will be added in the
future). The `-m`/`--metadata` option requires a path to a YAML file describing
package metadata. An example can be found in the directory `data`.

The results are stored in a subdirectory of the JSON directory that is defined
in the YAML configuration file:

```
json_directory: /home/bang/yara/json
```

The subdirectory will be the name of the package as defined in the metadata
file, for example:

```
package: busybox
```

This will result in the files being stored in the directory
`/home/bang/yara/json/busybox`.

In case there are new packages then not all files will have to be reprocessed:
only the new files need to be put into a new metadata file with just the new
archives.

The second step will be to run the YARA rule generation script:

    $ python3 yara_from_source.py -c /path/to/config --json-directory=/path/to/json/results -m /path/to/metadata

for example:

    $ python3 yara_from_source.py -c yara-config.yaml --json-directory=/home/bang/yara/json/busybox -m data/busybox.yaml

Optionally a pickle with low quality identifiers (example: `main()`) can be
passed as a parameter:

    $ python3 yara_from_source.py -c /path/to/config --json-directory=/path/to/json/results -m /path/to/metadata -i /path/to/pickle

for example:

    $ python3 yara_from_source.py -c yara-config.yaml --json-directory=/home/bang/yara/json/busybox -m data/busybox.yaml -i low_quality_identifiers.pickle

A pregenerated pickle can be found in this repository.

It is important that the metadata files for the extraction and YARA file
generation are in sync.

The results are stored in a subdirectory of the YARA directory that is defined
in the YAML configuration file:

```
yara_directory: /home/bang/yara
```

The subdirectory is called `src`.

### YAML package configuration

An example can be found in `data` and an edited version can be found below:

```
---
package: busybox
website: https://www.busybox.net/
packageurl: pkg:generic/busybox

releases: [
  pkg:generic/busybox@1.1.0: busybox-1.1.0.tar.bz2,
  pkg:generic/busybox@1.1.1: busybox-1.1.1.tar.bz2,

...

  pkg:generic/busybox@1.34.1: busybox-1.34.1.tar.bz2,
  pkg:generic/busybox@1.35.0: busybox-1.35.0.tar.bz2,
]
```

First is the name of the package, stored in the element `package`. Then there
is some metadata: `website` and `packageurl` (currently not used). Then follows
a list called `releases` containing elements. The key of the element is the
version of the package, preferably in package-url format[1]. If there is no
package-url available, then this should be the version, for example:

```
releases: [
  1.1.0: busybox-1.1.0.tar.bz2,
  1.1.1: busybox-1.1.1.tar.bz2,

...

  1.34.1: busybox-1.34.1.tar.bz2,
  1.35.0: busybox-1.35.0.tar.bz2,
]
```

Using package-url is strongly encouraged.

## Binary processor

The script takes result files of BANG scans (for example: Debian archive
files) and creates YARA files. Optionally it can use a list of low quality
identifiers that can be filtered to make the YARA rules simpler.

### Running BANG to extract identifiers

First you need to run BANG on a collection of files, for example all `.debs`
from Debian. It is recommended to use the following configuration options:

    removescandata = yes
    logging = no

These options will remove the scan output and prevents large log files to
be written as they will not be used by the YARA rule generator script.

Then run the script to generate the YARA files. The script has two mandatory
arguments: a configuration file (in YAML format) and the directory with BANG
scan results. An exanple configuration file `yara-config.yaml` is provided
in this directory and should be adapted to your local settings.

An example invocation could look like this:

    $ python3 yara_from_bang.py -c yara-config.yaml -r ~/tmp/debian

There are some settings in the configuration that determine which identifiers
will be written to the YARA files. These are described in the sample
configuration file.

It is possible to filter low quality identifiers (described later). These
should be passed to the script in Python pickle format:

    $ python3 yara_from_bang.py -c yara-config.yaml -r ~/tmp/debian -i low_quality_identifiers.pickle

### Low quality identifiers

There are several identifiers such as function names and variable names
that can be found in many binaries and that have generic names. Although
they can still be useful they can also lead to false positives if there are
only generic names. They also take up unnecessary space as YARA has a default
maximum number of rules (10,000).

Examples are:

* very short identifiers (a single character)
* identifiers that are a substring of other identifiers as these could lead to
false positives in YARA
* identifiers that occur in many packages. A good example: weak ELF symbols
<https://en.wikipedia.org/wiki/Weak_symbol>

A prefab list of low quality ELF identifiers can be found in the files
`low_quality_elf_funcs` and `low_quality_elf_vars`. These were handcrafted by
looking at all identifiers found in all ELF files in Debian 11.

# References

[1] https://github.com/package-url
