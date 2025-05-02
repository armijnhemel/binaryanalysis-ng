# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import quake_pak

'''
A Quake PAK file is a file used by the game Quake. It is basically
a concatenation of files with some extra metadata (file name), with
a lookup table.

https://quakewiki.org/wiki/.pak
'''


class QuakePakUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PACK')
    ]
    pretty_name = 'quakepak'

    def parse(self):
        try:
            self.data = quake_pak.QuakePak.from_io(self.infile)

            # there has to be at least one file.
            check_condition(self.data.len_index > 0, "at least one file needed")

            # size of the file table has to be a multiple of 64.
            check_condition(self.data.len_index%64 == 0, "file table not a multiple of 64")
            check_condition(len(self.data.index.entries) == self.data.len_index//64,
                           "not enough file entries")

            # hack: read the index entries to trigger that instances
            # are read.
            for i in self.data.index.entries:
                pass
        except ValidationFailedError as e:
            raise UnpackParserException(e.args)
        except EOFError as e:
            raise UnpackParserException(e.args)
        except Exception as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_index + self.data.len_index
        for i in self.data.index.entries:
            self.unpacked_size = max(self.unpacked_size, i.ofs + i.size)

    def unpack(self, meta_directory):
        unpacked_files = []
        seen_files = set()
        for quake_entry in self.data.index.entries:
            out_labels = []
            # there can be duplicate names, so rename
            # example: PROGS/OPENCP/CP.PAK in SOUND/OPENCP.ZIP in FD12CD.iso
            entry_name = quake_entry.name
            if entry_name in seen_files:
                counter=1
                while True:
                    entry_name = "%s-renamed-%d" % (quake_entry.name, counter)
                    if entry_name not in seen_files:
                        out_labels.append('renamed')
                        break
                    counter+=1

            file_path = pathlib.Path(entry_name)
            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, f):
                os.sendfile(f.fileno(), self.infile.fileno(), self.offset + quake_entry.ofs, quake_entry.size)

                # TODO: set original file name on unpacked_md if renamed
                with unpacked_md.open(open_file = False):
                    unpacked_md.info['labels'] = out_labels
                yield unpacked_md

            seen_files.add(entry_name)

    labels = ['quake', 'resource']
    metadata = {}
