# Examples

The following examples:

1. single Ogg file
2. single Ogg file, compressed with gzip
3. single Ogg file, with data prepended

## Example 1: single Ogg file

As an example let's unpack a single Ogg file called `test.ogg`. The file has
no contents to be unpacked, just metadata to extract.

Unpacking is invoked using the `scan` subcommand:

```
$ python3 -m bang.cli scan -u /tmp/unpack /tmp/test.ogg
```

This will create the following directory structure:

```
$ find -type f | sort
./root/info.pkl
./root/pathname
```

The meta directory for the root element is always stored in the directory
`root`. The file `root/pathname` stores the original file name:

```
$ cat root/pathname
/tmp/test.ogg
```

The file `root/info.pkl` is a Python pickle file containing data for the scan,
such as which parser was used, labels and other metadata.

The results of the scan for the roolt file can be shown by using the `show`
subcommand.

```
$ python3 -m bang.cli show --all /tmp/unpack/root
root (/tmp/test.ogg):
Parser: ogg
Labels: audio, ogg
Metadata:
{}
```

In this case the `--all` flag is given to show all the metadata for the scan.
For this file there is no metadata, so it is empty.

What is shown is the contents of the `info.pkl` file:

1. the name of the file
2. the name of the parser that was used
3. the labels that were given to the file
4. the metadata (empty in this case)

## Example 2: single Ogg file, compressed with gzip

For the second example the same Ogg file as in the first example has been
compressed with gzip and is unpacked:

```
$ python3 -m bang.cli scan -u /tmp/unpack /tmp/test.ogg.gz
```

The directory structure now looks different:

```
$ find -type f | sort
./8b8004ee7ba64ce988b99affb8d75013/info.pkl
./8b8004ee7ba64ce988b99affb8d75013/pathname
./root/info.pkl
./root/pathname
./root/rel/test.ogg
```

The big different for the `root` directory is that there is now an extra
directory called `rel` in which unpacked files are stored, in this case the
file `test.ogg` (the unpacker for `gzip` has some built in logic for guessing
the right file name). As in gzip compression files are compressed relatively
to the root of the file (as paths are not recorded) it is stored in `rel`.

The file `test.ogg` contains the contents of the Ogg file:

```
$ file root/rel/test.ogg
root/rel/test.ogg: Ogg data, Vorbis audio, stereo, 44100 Hz, ~120000 bps, created by: Xiph.Org libVorbis I (1.1.0 RC1)
```

The metadata of the root directory shows that a file was unpacked:

```
$ python3 -m bang.cli show --all /tmp/unpack/root/
root (/tmp/test.ogg.gz):
Parser: gzip
Labels: gzip, archive
Metadata:
{}
root/rel/test.ogg	8b8004ee7ba64ce988b99affb8d75013
```

The name `8b8004ee7ba64ce988b99affb8d75013` is the name of the meta directory
with the information of `test.ogg`, which can also be shown:

```
$ python3 -m bang.cli show --all /tmp/unpack/8b8004ee7ba64ce988b99affb8d75013/
8b8004ee7ba64ce988b99affb8d75013 (root/rel/test.ogg):
Parser: ogg
Labels: audio, ogg
Metadata:
{}
```

## Example 3: Ogg file with extra data prepended

If data is prepended or appended then files are first extracted from the
larger file (after the length has been validated) and then added back
into the queue.

In this example two bytes of random data (a space and a newline character) were
prepended to the Ogg file (not appended, as the Ogg parser has difficulty with
appended data) and scanned.

```
$ python3 -m bang.cli scan -u /tmp/unpack /tmp/test.ogg-prepended
```

The directory structure now looks as follows:

```
$ find -type f| sort
./abbfdb1d8cc9490ba1c1912ce2901dda/info.pkl
./abbfdb1d8cc9490ba1c1912ce2901dda/pathname
./e1eb829b24bc4d99b6616c5e549b37bd/info.pkl
./e1eb829b24bc4d99b6616c5e549b37bd/pathname
./root/extracted/000000000000-000000000002
./root/extracted/000000000002-0000000e4a97
./root/info.pkl
./root/pathname
```

The two parts of the root file (the two random bytes and the Ogg file) are
written to the directory `extracted`:

```
$ file root/extracted/*
root/extracted/000000000000-000000000002: ASCII text
root/extracted/000000000002-0000000e4a97: Ogg data, Vorbis audio, stereo, 44100 Hz, ~120000 bps, created by: Xiph.Org libVorbis I (1.1.0 RC1)
```

The file name of the extracted files contains the offset in the larger file
and the length of the data. For the Ogg file: it starts at offset `0x02` and
is `0xe4a97` bytes long.

Showing the results:

```
$ python3 -m bang.cli show --all /tmp/unpack/root/
root (/tmp/test.ogg-prepended):
Parser: None
Labels: 
Metadata:
None
root/extracted/000000000000-000000000002	e1eb829b24bc4d99b6616c5e549b37bd
root/extracted/000000000002-0000000e4a97	abbfdb1d8cc9490ba1c1912ce2901dda
```

The first carved file with the extra bytes is a so called "synthesized" file,
meaning that it is a file with leftovers that no parser could correctly parse
and should be inspected manually to see if there is any useful information
inside.

```
$ python3 -m bang.cli show --all /tmp/unpack/e1eb829b24bc4d99b6616c5e549b37bd
e1eb829b24bc4d99b6616c5e549b37bd (root/extracted/000000000000-000000000002):
Parser: synthesizingparser
Labels: synthesized
Metadata:
{}
```
