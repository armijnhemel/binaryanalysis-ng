# Showing unpacking results

## Printing the full unpacking tree

```
$ python3 -m bang.cli print-tree /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli print-tree /tmp/bang/root
```

To show a directory tree without the names of the meta directories in the
names of the files, use the `--pretty` flag:

```
$ python3 -m bang.cli print-tree --pretty /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli print-tree --pretty /tmp/bang/root
```

## Printing the results of a single file

```
$ python3 -m bang.cli show /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli show /tmp/bang/root
```

To also show which files were unpacked, add the `-a` flag:

```
$ python3 -m bang.cli show -a /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli show -a /tmp/bang/root
```

To show the results without the names of the meta directories in the names
of the files, use the `--pretty` flag:

```
$ python3 -m bang.cli show -a --pretty /path/to/metadirectory
```

for example:

```
$ python3 -m bang.cli show -a --pretty /tmp/bang/root
```
