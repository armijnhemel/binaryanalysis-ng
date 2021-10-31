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
from UnpackParser import UnpackParser
from UnpackParserException import UnpackParserException
from FileResult import FileResult
from kaitaistruct import ValidationFailedError

def rewrite_symlink(file_path, target_path):
    """rewrites a symlink of target_path, relative to file_path.
    target_path and file_path are both Path objects. Returns a
    Path object, representing a relative symlink.
    We assume that file_path is normalized.
    """
    file_path = pathlib.Path('/') / file_path
    target_res = (file_path.parent / target_path).resolve()
    target_dir_count = len(target_res.parts[1:-1])
    file_dir_count = len(file_path.parts[1:-1])
    if target_path.is_absolute():
        ddots = ['..'] * file_dir_count 
        link_path = pathlib.Path('.').joinpath(*ddots) \
                .joinpath(*target_res.parts[1:])
    else:
        ddots = ['..'] * min(file_dir_count, file_dir_count - target_dir_count)
        link_path = pathlib.Path('.').joinpath(*ddots) / target_path.name
    return link_path

class CpioBaseUnpackParser(UnpackParser):
    extensions = []
    signatures = []
    pretty_name = 'cpio'

    #def calculate_unpacked_size(self):
        #self.unpacked_size = self.infile.tell() - self.offset
        # the cpio(5) man page is unclear about the padding at the end of
        # the file. It looks like the file is padded to make the total
        # file size a multiple of 16, but more research is needed. For
        # now, we ignore the padding and accept a wrong size.

    def unpack_directory(self, filename):
        outfile_full = self.scan_environment.unpack_path(filename)
        os.makedirs(outfile_full, exist_ok=True)

    def unpack_regular(self, filename, start, length):
        self.extract_to_file(filename, start, length)

    def unpack_device(self, filename):
        pass

    def unpack_link(self, filename, target, rewrite=False):
        """we assume filename is normalized. If rewrite is True, symlinks are
        rewritten to point to other extracted files."""
        file_path = pathlib.Path(filename)
        target_path = pathlib.Path(target)
        if rewrite:
            link_path = rewrite_symlink(file_path, target_path)
        else:
            link_path = target_path

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile_full.symlink_to(link_path)

    def unpack(self):
        unpacked_files = []
        pos = 0
        for e in self.data.entries:
            out_labels = []
            if e.filename != self.data.trailing_filename:
                file_path = pathlib.Path(e.filename)
                if file_path.is_absolute():
                    file_path = file_path.relative_to('/')
                mode = e.header.cpio_mode
                outfile_rel = self.rel_unpack_dir / file_path
                if stat.S_ISDIR(mode):
                    self.unpack_directory(outfile_rel)
                elif stat.S_ISLNK(mode):
                    self.unpack_link(file_path, e.filedata.split(b'\x00')[0].decode())
                    out_labels.append('symbolic link')
                elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    self.unpack_device(outfile_rel)
                    pos += e.header.bsize
                    continue
                elif stat.S_ISREG(mode):
                    filedata_start = e.header.hsize + e.header.nsize + e.header.npaddingsize
                    self.unpack_regular(outfile_rel,
                            pos + filedata_start, e.header.fsize)

                fr = FileResult(self.fileresult,
                        self.rel_unpack_dir / file_path,
                        set(out_labels))
                unpacked_files.append( fr )
            pos += e.header.bsize
        return unpacked_files

    def set_metadata_and_labels(self):
        return

class CpioNewAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070701') ]

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
    pretty_name = 'cpio'

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
    pretty_name = 'cpio'

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
    pretty_name = 'cpio'

    def parse(self):
        try:
            self.data = cpio_old_binary.CpioOldBinary.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)
