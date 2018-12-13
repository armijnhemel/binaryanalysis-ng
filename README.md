# binaryanalysis-ng
Binary Analysis Next Generation (BANG)

BANG is a framework for unpacking files (like firmware) recursively and running checks on the unpacked files. Its intended use is to be able to find out the provenance of the unpacked files and classify/label files, making them available for further analysis.

## Requirements:

* a recent Linux distribution (Fedora 26 or higher, or equivalent)
* Python 3.6.x or higher (as some Python 3.6 specific features are used)
* pillow, a drop in replacement for PIL ( http://python-pillow.github.io/ )
* GNU binutils (for 'ar')
* squashfs-tools (for 'unsquashfs')
* cabextract
* 7z
* e2tools (for 'e2ls' and 'e2cp')
* zstd
* python-lz4 (possibly named python3-lz4)
* qemu-img (for VMDK files)
* psycopg2 (possibly named python3-psycopg2)
* python-snappy (possibly named python3-snappy)
* python-tlsh (possibly named python3-tlsh)
* tinycss2 (possibly named python3-tinycss2)
* dockerfile-parse (possibly named python3-dockerfile-parse)
* openssl
* rzip
* libxml2 (for 'xmllint')
* mailcap (for mime.types)
* lzop

## Invocation

    $ python3 bang-scanner -c bang.config -f /path/to/binary

## License

GNU Affero General Public License, version 3 (AGPL-3.0)

The code for unpacking D-Link ROMFS file systems was heavily inspired by
binwalk and modified (and improved) for use with BANG.

The original license for the binwalk code:

The MIT License (MIT)

Copyright (c) 2010-2015 Craig Heffner

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Developing

The recommended coding style is described in PEP 8:

https://www.python.org/dev/peps/pep-0008/

It is recommended to run PEP 8 verification tools, for example
python3-pep8 (on Fedora).
