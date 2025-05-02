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

import collections
import pathlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import exfat


class ExfatUnpacker(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xeb\x76\x90EXFAT   ')
    ]
    pretty_name = 'exfat'

    def parse(self):
        try:
            self.data = exfat.Exfat.from_io(self.infile)

            # walk the directory sets, starting with the root directory
            directory_sets = collections.deque()
            parent = ''
            for s in self.data.root_directory.directory_sets:
                directory_sets.append((s, parent))

            self.volume_label = ''
            while True:
                try:
                    directory_set, parent = directory_sets.popleft()
                    if directory_set.primary.end_of_directory:
                        continue

                    if directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Critical.Code.volume_label:
                        check_condition(self.volume_label == '', 'only one volume label allowed')
                        self.volume_label = directory_set.primary.data.data.data.label.decode('utf-16le').split('\x00', 1)[0]
                        check_condition(len(self.volume_label) == directory_set.primary.data.data.data.num_characters,
                                        'invalid volume label length')
                    elif directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Critical.Code.allocation_bitmap:
                        pass
                    elif directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Critical.Code.up_case_table:
                        pass
                    elif directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Critical.Code.file_directory:
                        name = ''
                        for s in directory_set.secondaries:
                            if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.file_name_directory:
                                name = s.data.data.data.name.decode('utf-16le').split('\x00', 1)[0]
                            elif s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.stream_extension:
                                # verify if this is a "no FAT chain" entry as
                                # that is the only one supported
                                if not s.data.data.data.no_fat_chain:
                                    check_condition(s.data.data.data.len_data == 0, "FAT chains currently not supported")
                        check_condition(name != '', 'entry cannot have empty name')

                        if directory_set.primary.data.data.data.directory:
                            # descend into the subdirectory
                            for s in directory_set.secondaries:
                                if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.stream_extension:
                                    for ds in s.data.data.data.subdirectory.directory_sets:
                                        directory_sets.append((ds, name))
                        else:
                            # force read the data to get Kaitai Struct to evaluate
                            for s in directory_set.secondaries:
                                if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.stream_extension:
                                    data = s.data.data.data.data
                    elif directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Benign.Code.volume_guid:
                        pass
                    elif directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Benign.Code.texfat_padding:
                        pass
                    else:
                        raise UnpackParserException("invalid primary partition")

                except IndexError:
                    break
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    def unpack(self, meta_directory):
        # walk the directory sets, starting with the root directory
        directory_sets = collections.deque()
        parent = ''
        for s in self.data.root_directory.directory_sets:
            directory_sets.append((s, parent))

        while True:
            try:
                directory_set, parent = directory_sets.popleft()
                if directory_set.primary.end_of_directory:
                    continue

                if directory_set.primary.data.data.type_code == exfat.Exfat.Directory.Entry.Primary.Critical.Code.file_directory:
                    name = ''
                    for s in directory_set.secondaries:
                        if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.file_name_directory:
                            name = s.data.data.data.name.decode('utf-16le').split('\x00', 1)[0]

                    file_path = pathlib.Path(parent, name)
                    if directory_set.primary.data.data.data.directory:
                        meta_directory.unpack_directory(file_path)

                        # descend into the subdirectory
                        for s in directory_set.secondaries:
                            if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.stream_extension:
                                for ds in s.data.data.data.subdirectory.directory_sets:
                                    directory_sets.append((ds, name))
                    else:
                        for s in directory_set.secondaries:
                            if s.data.data.type_code == exfat.Exfat.Directory.Entry.Secondary.Critical.Code.stream_extension:
                                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                                    if s.data.data.data.data is None:
                                        # this can happen for empty files: no_fat_chain will
                                        # not be set for these files, meaning that there will
                                        # not be a data element.
                                        outfile.write(b'')
                                    else:
                                        outfile.write(s.data.data.data.data)
                                    yield unpacked_md
            except IndexError:
                break

    labels = ['exfat', 'filesystem']

    @property
    def metadata(self):
        metadata = {'volume label': self.volume_label}
        return metadata
