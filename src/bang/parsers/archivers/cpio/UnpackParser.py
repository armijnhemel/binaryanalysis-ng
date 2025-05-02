# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# A description of the CPIO format can be found in section 5 of the
# cpio manpage on Linux:
# man 5 cpio
#
# This unpacker does not allow partial unpacking of (corrupt) cpio archives
#
# Some CPIO files, such as made on Solaris, that pack special
# device files such as doors and event ports, might fail to
# unpack on Linux.
# See https://bugs.python.org/issue11016 for background information
# about event ports, doors and whiteout files.

import os
import stat
import pathlib
from . import cpio_new_ascii
from . import cpio_new_crc
from . import cpio_portable_ascii
from . import cpio_old_binary

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from bang.log import log
from kaitaistruct import ValidationFailedError


class CpioBaseUnpackParser(UnpackParser):
    extensions = []
    signatures = []
    pretty_name = 'cpio-base'

    #def calculate_unpacked_size(self):
        #self.unpacked_size = self.infile.tell()
        # the cpio(5) man page is unclear about the padding at the end of
        # the file. It looks like the file is padded to make the total
        # file size a multiple of 16, but more research is needed. For
        # now, we ignore the padding and accept a wrong size.

    def unpack_directory(self, meta_directory, path):
        # we unpack the directory, but do not yield a MetaDirectory for it
        meta_directory.unpack_directory(path)
        return []

    def unpack_regular(self, meta_directory, path, start, length):
        with meta_directory.unpack_regular_file(path) as (unpacked_md, f):
            os.sendfile(f.fileno(), self.infile.fileno(), self.offset + start, length)
            yield unpacked_md

    def unpack_device(self, meta_directory, filename):
        return []

    def unpack_link(self, meta_directory, path, target, rewrite=False):
        # symlinks are not rewritten.
        meta_directory.unpack_symlink(path, target)
        log.debug(f'unpack_link: {path} -> {target}')
        return []

    def unpack(self, meta_directory):
        pos = 0
        for e in self.data.entries:
            log.debug(f'unpack: got entry {e.filename}')
            if e.filename in ['.', '..', '/']:
                pos += e.header.bsize
                continue
            if e.filename != self.data.trailing_filename:
                file_path = pathlib.Path(e.filename)

                mode = e.header.cpio_mode
                log.debug(f'unpack: entry has mode {mode}')

                if stat.S_ISDIR(mode):
                    yield from self.unpack_directory(meta_directory, file_path)
                elif stat.S_ISLNK(mode):
                    yield from self.unpack_link(meta_directory, file_path, e.filedata.split(b'\x00')[0].decode())
                elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    yield from self.unpack_device(meta_directory, file_path)
                    pos += e.header.bsize
                    continue
                elif stat.S_ISREG(mode):
                    log.debug(f'unpack: regular file')

                    filedata_start = e.header.hsize + e.header.nsize + e.header.npaddingsize
                    yield from self.unpack_regular(meta_directory, file_path, pos + filedata_start, e.header.fsize)

            pos += e.header.bsize

    labels = ['cpio']
    metadata = {}

class CpioNewAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070701') ]
    pretty_name = 'cpio-new-ascii'

    def parse(self):
        try:
            self.data = cpio_new_ascii.CpioNewAscii.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

class CpioNewCrcUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070702') ]
    pretty_name = 'cpio-new-crc'

    def parse(self):
        try:
            self.data = cpio_new_crc.CpioNewCrc.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

class CpioPortableAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070707') ]
    pretty_name = 'cpio-portable-ascii'

    def parse(self):
        try:
            self.data = cpio_portable_ascii.CpioPortableAscii.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

class CpioOldBinaryUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'\xc7\x71') ]
    pretty_name = 'cpio-old-bin'

    def parse(self):
        try:
            self.data = cpio_old_binary.CpioOldBinary.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)
