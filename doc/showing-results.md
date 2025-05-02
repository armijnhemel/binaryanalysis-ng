# Showing unpacking results

In BANG there are a few ways you can show the results of the unpacking process:

1. interactive TUI (text user interface)
2. CLI interface for pretty printing data to standard out, or files

## TUI

A TUI (text user interface) can be a quick and easy way to browse (and
eventually search) results. [Textual][textual] and [Rich][rich] are very
suited for this task.

```
$ python3 -m bang.bang_shell -r /path/to/metadirectory
```

## CLI

1. full unpacking tree
2. data for individual files

### Printing the full unpacking tree

```
$ python3 -m bang.cli print-tree /path/to/metadirectory
```

for example (on a scan of the `/bin/ls` program):

```
$ python3 -m bang.cli print-tree /tmp/bang/root
/bin/ls
└── root/rel/.gnu_debugdata
    └── 3adbaa353d70408aa775d07d551d8f33/rel/unpacked_from_xz
```

To show a directory tree without the names of the meta directories in the
names of the files, use the `--pretty` flag:

```
$ python3 -m bang.cli print-tree --pretty /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli print-tree --pretty /tmp/bang/root
ls
└── /.gnu_debugdata
    └── /unpacked_from_xz
```

### Printing the results of a single file

```
$ python3 -m bang.cli show /path/to/metadirectory
```

for example (for the results of a scan of `/bin/ls`):

```
$ python3 -m bang.cli show /tmp/bang/root
                                         Parser data
┌────────────────┬──────────────────────────────────────────────────────────────────────────┐
│ Meta directory │ root                                                                     │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Original file  │ /bin/ls                                                                  │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Parser         │ elf                                                                      │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Labels         │ elf, dynamic                                                             │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Size           │ 142088                                                                   │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha256         │ 379bd02606e11961d007bfe595b50d7e8ca28c2fb57c9021e2fbe622347c3c12         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ md5            │ 4bb5074fd819c9f539870e42fa5e91f4                                         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha1           │ 9457a9c1d5c46871848c50eb56d318f024c518a6                                 │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ tlsh           │ T1DCD35A17F29204BEC4C48071CAA79A62BE30FC6C53217B3B399CB6351F56B645B6A770 │
└────────────────┴──────────────────────────────────────────────────────────────────────────┘
```

To also show which files were unpacked, add the `-a` flag:

```
$ python3 -m bang.cli show -a /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli show -a /tmp/bang/root
                                         Parser data
┌────────────────┬──────────────────────────────────────────────────────────────────────────┐
│ Meta directory │ root                                                                     │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Original file  │ /bin/ls                                                                  │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Parser         │ elf                                                                      │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Labels         │ elf, dynamic                                                             │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Size           │ 142088                                                                   │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha256         │ 379bd02606e11961d007bfe595b50d7e8ca28c2fb57c9021e2fbe622347c3c12         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ md5            │ 4bb5074fd819c9f539870e42fa5e91f4                                         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha1           │ 9457a9c1d5c46871848c50eb56d318f024c518a6                                 │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ tlsh           │ T1DCD35A17F29204BEC4C48071CAA79A62BE30FC6C53217B3B399CB6351F56B645B6A770 │
└────────────────┴──────────────────────────────────────────────────────────────────────────┘
                                      Unpacked
┏━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Nr ┃ Name                    ┃ Labels         ┃ Meta directory                   ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  1 │ root/rel/.gnu_debugdata │ compressed, xz │ 3adbaa353d70408aa775d07d551d8f33 │
└────┴─────────────────────────┴────────────────┴──────────────────────────────────┘
```

To show the results without the names of the meta directories in the names
of the files, use the `--pretty` flag:

```
$ python3 -m bang.cli show -a --pretty /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli show -a --pretty /tmp/bang/root
                                         Parser data
┌────────────────┬──────────────────────────────────────────────────────────────────────────┐
│ Meta directory │ root                                                                     │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Original file  │ /bin/ls                                                                  │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Parser         │ elf                                                                      │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Labels         │ elf, dynamic                                                             │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ Size           │ 142088                                                                   │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha256         │ 379bd02606e11961d007bfe595b50d7e8ca28c2fb57c9021e2fbe622347c3c12         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ md5            │ 4bb5074fd819c9f539870e42fa5e91f4                                         │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ sha1           │ 9457a9c1d5c46871848c50eb56d318f024c518a6                                 │
├────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ tlsh           │ T1DCD35A17F29204BEC4C48071CAA79A62BE30FC6C53217B3B399CB6351F56B645B6A770 │
└────────────────┴──────────────────────────────────────────────────────────────────────────┘
                                  Unpacked
┏━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Nr ┃ Name            ┃ Labels         ┃ Meta directory                   ┃
┡━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  1 │ /.gnu_debugdata │ compressed, xz │ 3adbaa353d70408aa775d07d551d8f33 │
└────┴─────────────────┴────────────────┴──────────────────────────────────┘
```

To print the results of a file other than the `root` entry you need to know the
meta directory of the file first. You can see this when running `show` with the
`-a` flag and then checking the `meta directory` column of the unpacked file.

Using the example from above, to inspect the data of the file `.gnu_debugdata`
you would use the value of the meta directory for this file instead of `root`:

```
$ python3 -m bang.cli show -a /tmp/bang/3adbaa353d70408aa775d07d551d8f33
                                     Parser data
┌────────────────┬──────────────────────────────────────────────────────────────────┐
│ Meta directory │ 3adbaa353d70408aa775d07d551d8f33                                 │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ Original file  │ root/rel/.gnu_debugdata                                          │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ Parser         │ xz                                                               │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ Labels         │ compressed, xz                                                   │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ Size           │ 2776                                                             │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ sha256         │ b1f40e0d110ad0a3080d623c65ac3e8119c9b5790e3557ab05fc7a1ebbdad0c4 │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ md5            │ 946e9b911de2c4749ffc337dfaca25a1                                 │
├────────────────┼──────────────────────────────────────────────────────────────────┤
│ sha1           │ c89a83defed93f060fbb5320933d9052c353d71b                         │
└────────────────┴──────────────────────────────────────────────────────────────────┘
                                                   Unpacked
┏━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Nr ┃ Name                                                  ┃ Labels      ┃ Meta directory                   ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  1 │ 3adbaa353d70408aa775d07d551d8f33/rel/unpacked_from_xz │ elf, static │ c292e801f4ee49c8acacbf6157c97b49 │
└────┴───────────────────────────────────────────────────────┴─────────────┴──────────────────────────────────┘
```

### Printing the results of all files

To show the results of all files (basically, a recursive version of printing
the results of a single file) can be done with the `report` subcommand:

```
$ python3 -m bang.cli report /path/to/metadirectory
```

[rich]:https://github.com/Textualize/rich
[textual]:https://github.com/Textualize/textual
