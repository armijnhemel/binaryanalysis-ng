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

## Invocation

    $ python3 bang-scanner -c bang.config -f /path/to/binary

## License

GNU Affero General Public License, version 3 (AGPL-3.0)

## Developing

The recommended coding style is described in PEP 8:

https://www.python.org/dev/peps/pep-0008/

It is recommended to run PEP 8 verification tools, for example
python3-pep8 (on Fedora).
