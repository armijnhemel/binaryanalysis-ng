# Semgrep & Semgrep rules

This directory contains some rules for Semgrep <https://semgrep.dev/> that
are based on the CERT C coding standard.

## Example rules

Currently there rules defined for two CERT recommendation:

* ENV33-C
* MSC24-C

These can be found in the directory `c`.

## Using rules

After installing the `semgrep` tool you can run it using the two rules:

```
$ semgrep --quiet --config=c /path/to/source/directory/

```
for example:

```
$ semgrep --quiet --config=c ~/git/busybox/
```

To output JSON and redirect it to a file use:

```
$ semgrep --quiet --config=c /path/to/source/directory/ --json > /path/to/output
```

for exmaple:

```
$ semgrep --quiet --config=c ~/git/busybox/ --json > /tmp/busybox.json
```
