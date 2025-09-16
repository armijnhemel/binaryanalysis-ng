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

import pathlib
import gzip

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import plf

# mapping of section types to possible names, taken from:
#
# https://github.com/scorp2kk/ardrone-tool/blob/1f342d3df36af70f22341/projects/plftool/plftool.c#L64
#
# This mapping is not necessarily correct and doesn't work
# nicely for all .plf files (such as zik_release_2.05.plf )
# so do not use this for now.
SECTION_TO_NAMES = {'executable': {0: 'zimage',
                                   3: 'initrd',
                                   7: 'bootparams.txt'},
                    'archive': {3: 'main_boot.plf',
                                7: 'bootloader.bin',
                                9: 'file_action',
                                11: 'volume_config',
                                12: 'installer.plf'}
                   }


class PlfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PLF!')
    ]
    pretty_name = 'plf'

    def parse(self):
        try:
            self.data = plf.Plf.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    def unpack(self, meta_directory):
        unpacked_files = []

        # directory for storing file system data from partitions
        # with type 0x09
        file_system_data_directory = None

        # directory for storing file system data from partitions
        # with type 0x04 and 0x05
        data_directory = None
        have_mapping = False
        if self.data.header.file_type.name in SECTION_TO_NAMES:
            have_mapping = True

        partition_names = set()

        counter = 1
        for partition in self.data.partitions.partitions:
            out_labels = []
            compressed = False

            if partition.uncompressed_size != 0:
                # compressed data
                compressed = True
                try:
                    data = gzip.decompress(partition.data)
                except:
                    continue
            else:
                # uncompressed data
                data = partition.data

            # some partitions need to be treated differently than
            # others. For example, the separate partitions with type
            # 0x09 are actually inodes, not separate partitions, so
            # should be unpacked together instead of separately.
            if partition.section_type == plf.Plf.SectionTypes.section9:
                # put all the unpacked inodes in a separate directory.
                # This is ugly, but practical.
                data_dir_rel = pathlib.Path('file_system_data')

                # data consist the file name, followed by 8 bytes
                # of metadata and then the file data
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = data_dir_rel / entry_name.decode()
                except:
                    continue

                entry_tag = entry_data[:4]
                entry_flags = int.from_bytes(entry_tag, byteorder='little')
                entry_filetype = entry_flags >> 12

                if entry_filetype == 0x4:
                    # create directory
                    meta_directory.unpack_directory(file_path)
                elif entry_filetype == 0x8:
                    # write data, skip the first 12 bytes of the data
                    # (entry tag, plus 8 bytes of other information)
                    with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                        outfile.write(entry_data[12:])
                        yield unpacked_md
                elif entry_filetype == 0xa:
                    # symlink, only process if not compressed
                    if compressed:
                        continue
                    try:
                        target_name = entry_data[12:].split(b'\x00', 1)[0].decode()
                    except:
                        continue
                    meta_directory.unpack_symlink(file_path, target_name)

            elif partition.section_type == plf.Plf.SectionTypes.section4:
                # data consists of the file name, followed by the file data
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = pathlib.Path('data') / entry_name.decode()
                except:
                    continue

                # then write the data
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(entry_data)
                    yield unpacked_md
            elif partition.section_type == plf.Plf.SectionTypes.section5:
                # this section only creates directories
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = pathlib.Path('data') / entry_name.decode()
                except:
                    continue

                if file_path == pathlib.Path('/'):
                    continue

                meta_directory.unpack_directory(file_path)
            elif partition.section_type == plf.Plf.SectionTypes.section11:
                pass
            else:
                partition_name = f"partition-{counter}"
                '''
                if have_mapping:
                    if partition.section_type.value in SECTION_TO_NAMES[self.data.header.file_type.name]:
                        partition_name = SECTION_TO_NAMES[self.data.header.file_type.name][partition.section_type.value]
                        if partition_name in partition_names:
                            partition_name = "%s-%d" % (partition_name, counter)
                partition_names.add(partition_name)
                '''
                file_path = pathlib.Path(partition_name)
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    outfile.write(partition.data)
                    yield unpacked_md

            counter += 1

        return unpacked_files

    labels = ['plf', 'filesystem']
    metadata = {}
