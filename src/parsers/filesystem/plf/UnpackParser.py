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


import os
import pathlib
import gzip

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_plf(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = plf.Plf.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # no need to carve from the file
    #def carve(self):
    #    pass

    def unpack(self):
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
            # should be unpacked together.
            if partition.section_type == plf.Plf.SectionTypes.section9:
                data_dir_rel = self.rel_unpack_dir / 'file_system_data'
                if file_system_data_directory is None:
                    file_system_data_directory = self.scan_environment.unpack_path(data_dir_rel)
                    file_system_data_directory.mkdir()

                # data consist the file name, followed by 8 bytes
                # of metadata and then the file data
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = pathlib.Path(entry_name.decode())
                except:
                    continue

                entry_tag = entry_data[:4]
                entry_flags = int.from_bytes(entry_tag, byteorder='little')
                entry_filetype = entry_flags >> 12

                # then process based on the file type
                outfile_rel = data_dir_rel / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)

                if entry_filetype == 0x4:
                    # create directory
                    os.makedirs(outfile_full, exist_ok=True)

                    # add result to result set
                    fr = FileResult(self.fileresult, outfile_rel, set(['directory']))
                    unpacked_files.append(fr)
                elif entry_filetype == 0x8:
                    # write data, skip the first 12 bytes of the data
                    # (entry tag, plus 8 bytes of other information)
                    outfile_full.parent.mkdir(exist_ok=True)
                    outfile = open(outfile_full, 'wb')
                    outfile.write(entry_data[12:])
                    outfile.close()

                    # add result to result set
                    fr = FileResult(self.fileresult, outfile_rel, set())
                    unpacked_files.append(fr)

                elif entry_filetype == 0xa:
                    # symlink, only process if not compressed
                    if compressed:
                        continue
                    try:
                        target_name = entry_data[12:].split(b'\x00', 1)[0].decode()
                    except:
                        continue
                    outfile_full.symlink_to(target_name)

                    # add result to result set
                    fr = FileResult(self.fileresult, outfile_rel, set(['symbolic link']))
                    unpacked_files.append(fr)

            elif partition.section_type == plf.Plf.SectionTypes.section4:
                data_dir_rel = self.rel_unpack_dir / 'data'
                if data_directory is None:
                    data_directory = self.scan_environment.unpack_path(data_dir_rel)
                    data_directory.mkdir()

                # data consist the file name, followed by the file data
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = pathlib.Path(entry_name.decode())
                except:
                    continue

                # then write the data
                outfile_rel = data_dir_rel / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                outfile_full.parent.mkdir(exist_ok=True)

                outfile = open(outfile_full, 'wb')
                outfile.write(entry_data)
                outfile.close()

                # add result to result set
                fr = FileResult(self.fileresult, outfile_rel, set())
                unpacked_files.append(fr)
            elif partition.section_type == plf.Plf.SectionTypes.section5:
                data_dir_rel = self.rel_unpack_dir / 'data'
                if data_directory is None:
                    data_directory = self.scan_environment.unpack_path(data_dir_rel)
                    data_directory.mkdir()
                entry_name, entry_data = data.split(b'\x00', 1)
                if entry_name == b'':
                    continue
                try:
                    file_path = pathlib.Path(entry_name.decode())
                except:
                    continue

                if file_path == pathlib.Path('/'):
                    continue

                outfile_rel = data_dir_rel / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)

                # create directory
                os.makedirs(outfile_full, exist_ok=True)

                # add result to result set
                fr = FileResult(self.fileresult, outfile_rel, set(['directory']))
                unpacked_files.append(fr)
            elif partition.section_type == plf.Plf.SectionTypes.section11:
                pass
            else:
                partition_name = "partition-%d" % counter
                '''
                if have_mapping:
                    if partition.section_type.value in SECTION_TO_NAMES[self.data.header.file_type.name]:
                        partition_name = SECTION_TO_NAMES[self.data.header.file_type.name][partition.section_type.value]
                        if partition_name in partition_names:
                            partition_name = "%s-%d" % (partition_name, counter)
                partition_names.add(partition_name)
                '''
                file_path = pathlib.Path(partition_name)
                outfile_rel = self.rel_unpack_dir / file_path
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                outfile.write(partition.data)
                outfile.close()
                fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
                unpacked_files.append(fr)
            counter += 1

        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['plf', 'filesystem']
        metadata = {}

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
