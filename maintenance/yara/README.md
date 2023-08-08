# YARA rule generation scripts

This directory contains scripts to generate YARA rules. There are various scripts:

1. script to generate JSON from BANG results (binary files), plus a separate
script to generate YARA files from the JSON results, possibly doing some extra
filtering.
2. script to generate YARA rules from source code

The script to generate JSON files from binaries currently only supports ELF
and Android Dex. More formats will be added soon.

## When to use which processor

There are situations where it is better to use rules generated from source
code than rules generated from binaries.

The benefit of generating rules from binaries is that you do not need to
have access to the source code to create YARA files. The drawback is that
not every binary is well suited for this, due to how the binaries are
created or processed.

Generating rules from binaries seems to work really well for the vast
majority of dynamically linked ELF binaries but not for for example
statically linked ELF binaries or Dalvik `.dex` files.

### Dynamically linked ELF binaries

Dynamically linked ELF binaries are created from object files that are
in turned created from source code files. Dependencies (like third parties)
typically do not end up in the dynamically linked ELF file (although there
are of course exceptions, for example when there is a complete copy of
third party software included in the package), so the separation between
package and third party code tends to be clean. Information extracted from
binaries in a package usually is from just that package.

Extracting identifiers from the binary has advantages over extracting
identifiers from the source code: in many packages not all source code files
are used for building a specific program, so there might be too many
identifiers in a fingerprint.

For programs written in C++ there is also a difference between function names
and variable names in source code and binary code: in binary code these are
typically in so called "mangled form" and first need to be demangled when
using fingerprints generated from source code. When using fingerprints
extracted from binaries this step can be skipped.

### Statically linked ELF binaries

Statically linked ELF binaries not only include the data from the program
itself, but also code from dependencies that are used, for example the C
library. Because in ELF static linking there are no symbols that are imported
or exported (as all have already been resolved during the linking process) the
only identifiers that can be used are strings, and function names and variable
names cannot be used (as they are not present).

Because all of the dependencies are included in the same binary it means that
not just the strings of the program, but also the strings from its dependencies
are extracted by BANG. This makes strings extracted from a statically linked
ELF binary perhaps not the best suited if the goal is to only fingerprint only
a single program and not also all of the dependencies.

The strings can still be useful for fingerprinting statically linked binaries
that were built using the exact same configuration and combination of program
and dependencies.

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

This makes rules generated from binary `.dex` files not very well suited as
there will be a lot of junk. Results will be much better with rules created
from source code with other identifiers than class names or method names,
such as the strings embedded in `.dex` files.

The rules for strings from Android Dex files can contain some control
characters that will not be present in similar rules for ELF files. This is
because when extracting strings from Dex files it is guaranteed that the
control characters are part of the string and it is not extracted from a larger
blob containing possible garbage.

## Source code processor

The source code processor is split into two scripts:

1. `bang_extract_identifiers.py` - extracts identifiers from source code files and
   writes these identifiers, with associated metadata, to output files as JSON.
2. `yara_from_source.py` - takes JSON output files from step 1 and generates
   YARA rule files.

### `bang_extract_identifiers.py`

The `bang_extract_identifiers.py` script takes source code archives, unpacks
them and extracts data using `ctags` and `xgettext`. These identifiers are
written to JSON files together with associated metadata. The metadata is
defined in YAML files.

An example metadata file can be found in the directory `data`. A simplified
version of this file can be found below:

```
---
package: busybox
website: https://www.busybox.net/
packageurl: pkg:generic/busybox
cpe: cpe:/a:busybox:busybox:-
cpe23: cpe:2.3:a:busybox:busybox:-:*:*:*:*:*:*:*

releases: [
  pkg:generic/busybox@1.1.0: busybox-1.1.0.tar.bz2,
]
```

In the metadata file `package`, `packageurl` and `releases` are mandatory.

The script is invoked as follows:

```console
    $ python3 bang_extract_identifiers.py -c /path/to/config -s /path/to/sources -m /path/to/metadata
```

for example:

```console
    $ python3 bang_extract_identifiers.py -c yara-config.yaml -s ~/busybox -m data/busybox.yaml
```

The files mentioned in the metadata file should exist in the source code
directory. By default entries that do not exist are silently ignored, unless
`error_fatal` is set in the configuration file (in the section `general`).

The JSON output is stored in a directory, which can be set in the configuration
file (`json_directory` in the section `yara`). Inside this directory there is
a subdirectory per package (`package` in the metadata file) with one JSON file
per version defined in the metadata file.

The script depends on the extension of the file to determine
the most likely programming language used in the source code file. Current
focus is on C/C++, Java (including Scala and Kotlin) and Javascript. Support
for more languages will be added in the future.

The directory with source code should contain source code archives (currently
only TAR archives are supported, support for ZIP files will be added in the
future).

The script extracts _all_ identifiers from the source code, except empty
strings and strings containing only whitespace characters, as these are useless
for fingerprinting. All other identifiers are extracted.

### `yara_from_source.py`

The script `yara_from_source.py` takes the JSON output and generates YARA
files.

The script takes a few parameters: a configuration file, a directory with JSON
files, a pickle with low quality identifiers and a file with meta information
(typically the same file used for extraction of identifiers).

It can be invoked as follows:

```console
$ python3 yara_from_source.py -c yara-config.yaml -j /path/to/json/directory -i /path/to/pickle -m /path/to/metadata
```

for example:

```console
$ python3 yara_from_source.py -c yara-config.yaml -j ~/yara/json -i low_quality_identifiers.pickle -m data/busybox.yaml
```

The top level directory to store YARA files can be set in the configuration file
(`yara_directory` in the section `yara`). The files are stored in the
subdirectory `src`. Underneath this directory there will be a subdirectory
per packageurl type (for example: `generic`). This directory contains package
level YARA files with the union and intersection of identifiers of _all_
versions per programming language category (example:
`busybox-intersection-c.yara` and `busybox-union-c.yara`)

For each package there is a subdirectory (for example: `busybox`) with YARA
files per programming language category for each individual version of the
package.

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

Then run the script to generate the JSON files with identifiers.

The script has two mandatory arguments: the directory with BANG scan results
and an output directory to write the JSON files.

If a package was unpacked in the directory `~/tmp/debian`, and the output
directory would be `~/json` then an example invocation could look like this:

```console
$ python3 bang_to_json.py -o ~/json -r ~/tmp/debian/root
```

This will generate a JSON file for each ELF file that was unpacked from the
package. The script will recurse into the file structure that was unpacked by
BANG (so file systems, compressed archives, and so on).

It is possible to filter low quality identifiers (described later). These
should be passed to the script in Python pickle format:

```console
$ python3 bang_to_json.py -o ~/json -r ~/tmp/debian/root -i low_quality_identifiers.pickle
```

Another optional parameter is the number of jobs to run in parallel. This can
be useful if the number of result directories is large.

As the next step run the `yara_from_bang.py` for each of the generated JSON
files.

The script has two mandatory arguments: a configuration file (in YAML format)
and path to the JSON result file. An example configuration file
`yara-config.yaml` is provided in this directory and should be adapted to
your local settings.

For example:

```console
$ python3 yara_from_bang.py -c yara-config.yaml -j ~/json/classes.dex-1c632fc98e0a19d657ac5cdab83a9433668fa97e1142ead29de1e34effede149.json
```

# Low quality identifiers

There are several identifiers such as function names and variable names
that can be found in many binaries and that have generic names. Although
they can still be useful they can also lead to false positives if there are
only generic names. They also take up unnecessary space as YARA has a default
maximum number of rules (10,000).

## Low quality function names and variable names

Examples are:

* very short identifiers (a single character)
* identifiers that are a substring of other identifiers as these could lead to
  false positives in YARA (somewhat prevented by using `fullword` in YARA
  rules.
* identifiers that occur in many packages. A good example: weak ELF symbols
  <https://en.wikipedia.org/wiki/Weak_symbol> or identifiers that occur in
  packages that have been copied (cloned) and are included as "third party
  code" such as `zlib`, `libpng`, `sqlite` and so on.

A prefab list of low quality ELF identifiers can be found in the files
`low_quality_elf_funcs` and `low_quality_elf_vars`. These were collected by
looking at all identifiers found in (nearly) all ELF files in Debian 11.

Third party code is not yet labeled as such.

## Low quality strings

Similar to the function names and variable names there are also low quality
strings. Some examples are:

* very short identifiers (a single character)
* identifiers that are a substring of other identifiers as these could lead to
  false positives in YARA (somewhat prevented by using `fullword` in YARA
  rules.
* strings that appear in many packages. Good examples are strings that are
  present in packages that have been copied (cloned) and are included as "third
  party code" such as `zlib`, `libpng`, `sqlite` and so on.
* country names, timezones, names of device files (`/dev/null`, etc.),
  MIME types, HTTP headers
* strings from frameworks (example: Boost)
* strings from embedded interpreters or runtimes (example: OCaml)


A prefab list of low quality strings from ELF files can be found in the file
`low_quality_elf_strings`. These were collected by looking at all strings
found in (nearly) all ELF files in Debian 11.

# References

[1] https://github.com/package-url
