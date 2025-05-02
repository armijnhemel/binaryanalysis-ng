# YARA rules

This directory contains several rules for copyright, licenses, forges and
some security smells that can be used with YARA
(<https://virustotal.github.io/yara/>).

None of these rules are meant 100% correct and should only be used as a
starting point for further analysis.

It should be noted that although YARA is primarily intended for binary files
it can also be used for source code files.

BANG will support all the rules described below. In case you want to use the
rules without using BANG, but only with pure YARA, that is also possible.

## Copyright

A very simple generic copyright rule (searching for the word `copyright`) can
be found in the file `copyright.yara`.

The file can be used directly by YARA, but also first compiled to reduce load
time:

    $ yarac copyright.yara copyright.yarac

The precompiled version can then be used as follows:

    $ yara -C copyright.yarac /path/to/file/to/be/scanned

Example:

    $ yara -C copyright.yarac /bin/ls
    copyright /bin/ls

To get a bit more information use the `-s` option:

    $ yara -sC copyright.yarac /bin/ls
    copyright /bin/ls
    0x175e0:$string1: Copyright
    0x1786d:$string1: Copyright
    0x17908:$string1: copyright

## Licenses

For some licenses rules can be found in the directory `licenses`. These rules
are far from complete and not accurate. It is very likely there are false
positives and false negatives. Results should be regarded as a starting point
for a further investigation.

The file can be used directly by YARA, but also first compiled to reduce load
time:

    $ yarac licenses.yara licenses.yarac

The precompiled version can then be used as follows:

    $ yara -C licenses.yarac /bin/ls
    gnu /bin/ls
    gpl /bin/ls
    gpl30 /bin/ls
    gpl30_or_later /bin/ls
    license /bin/ls

To get a bit more information use the `-s` option:

    $ yara -sC licenses.yarac /bin/ls
    gnu /bin/ls
    0x1b190:$string1: gnu.org/licenses/
    0x1af34:$string3: gnu.org/software/
    gpl /bin/ls
    0x1b190:$string1: gnu.org/licenses/gpl.
    gpl30 /bin/ls
    0x1b0e0:$string3: GPLv3
    gpl30_or_later /bin/ls
    0x1b0d8:$string1: License GPLv3+: GNU GPL version 3 or later
    0x1b0e0:$string2: GPLv3+
    0x1b0d8:$re1: License GPLv3+: GNU GPL version 3 or later
    license /bin/ls
    0x1b0d8:$string1: License
    0x1b198:$string1: license

## Forges

For some forges rules can be found in the directory `forges`. These rules
are far from complete and not accurate. It is very likely there are false
positives and false negatives. Results should be regarded as a starting point
for a further investigation.

Forge references were extracted from various sources:

 <https://en.wikipedia.org/wiki/Forge_(software)>

and quite a few from Fedora:

    $ cd /usr/share/doc
    $ grep -r git  | grep http

and then manually processing results.

The file can be used directly by YARA, but also first compiled to reduce load
time:

    $ yarac forges.yara forges.yarac

The precompiled version can then be used as follows:

    $ yara -C forges.yarac /bin/gettext
    gnu_savannah /bin/gettext

To get a bit more information use the `-s` option:

    $ yara -sC forges.yarac /bin/gettext
    gnu_savannah /bin/gettext
    0x5aa8:$string1: savannah.gnu.org

## Security

The file `security.yara` contains rules for some security bugs. These were
largely inspired by American Express' EarlyBird tool:

<https://github.com/americanexpress/earlybird/>

which has been released under the Apache 2 license.

## Combining all rules

All rules can be combined as well. Combining different precompiled rules is not
possible, so you would need to use the regular rules. As there (currently) is
some overlap between rule names you need to provide the correct namespace as
well, for example:

    $ yara licenses:licenses.yara copyright.yara forges:forges.yara /bin/gettext
    gnu /bin/gettext
    gpl /bin/gettext
    gpl30 /bin/gettext
    gpl30_or_later /bin/gettext
    license /bin/gettext
    copyright /bin/gettext
    gnu_savannah /bin/gettext

or when needing more information:

    $ yara -s licenses:licenses.yara copyright.yara forges:forges.yara /bin/gettext
    gnu /bin/gettext
    0x5588:$string1: gnu.org/licenses/
    0x5160:$string4: @gnu.org
    gpl /bin/gettext
    0x5588:$string1: gnu.org/licenses/gpl.
    gpl30 /bin/gettext
    0x54d8:$string3: GPLv3
    gpl30_or_later /bin/gettext
    0x54d0:$string1: License GPLv3+: GNU GPL version 3 or later
    0x54d8:$string2: GPLv3+
    0x54d0:$re1: License GPLv3+: GNU GPL version 3 or later
    license /bin/gettext
    0x54d0:$string1: License
    0x5590:$string1: license
    copyright /bin/gettext
    0x54a0:$string1: Copyright
    gnu_savannah /bin/gettext
    0x5aa8:$string1: savannah.gnu.org

There are different options that `yara` can take to display more information,
for example the tags:

    $ yara -g licenses:licenses.yara copyright.yara forges:forges.yara /bin/gettext
    gnu [license] /bin/gettext
    gpl [license] /bin/gettext
    gpl30 [license] /bin/gettext
    gpl30_or_later [license] /bin/gettext
    license [license] /bin/gettext
    copyright [] /bin/gettext
    gnu_savannah [forge] /bin/gettext

which makes it easier to filter using the `-t` option, for example:

    $ yara licenses:licenses.yara copyright.yara forges:forges.yara -t license /bin/gettext
    gnu /bin/gettext
    gpl /bin/gettext
    gpl30 /bin/gettext
    gpl30_or_later /bin/gettext
    license /bin/gettext
