# cvehound

This directory contains a script to process the output of running `cvehound`
on Linux kernel source trees and processing the output.

Note: anything older than Linux kernel 2.6 seems to be (currently) unsupported
by `cvehound` 1.0.9 and earlier. It is recommended to use `cvehound` later
than 1.0.9.

## Running `cvehound`

```
$ cvehound -k /path/to/kernel/sources/ --report /path/to/output/json
```

for example:

```
$ cvehound -k ~/git/linux/ --report /tmp/report.json
```

It seems that `cvehound` cannot write to `stdout`.

## Example output (pretty printed)

By default `cvehound` prints output on `stdout`. It looks like this:

```
$ cvehound -k ~/git/linux/
Found: CVE-2020-25671
Found: CVE-2020-25670
```

## Processing JSON output

TODO
