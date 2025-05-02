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

# /usr/share/magic
# https://en.wikipedia.org/wiki/MINIX_file_system
# https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/fs/mfs
# https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/usr.sbin/mkfs.mfs/v1l

import pathlib
import stat

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import minix1l


class Minix1lUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x410, b'\x8f\x13')
    ]
    pretty_name = 'minix'

    def parse(self):
        try:
            self.data = minix1l.Minix1l.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.inode_to_name = {}
        self.inode_to_name[1] = pathlib.Path('')
        is_root_inode = True

        # walk all the inodes, the root inode is always 1
        inode_counter = 1
        for i in self.data.inodes:
            # skip empty inodes
            if i.mode == 0:
                inode_counter += 1
                continue

            # the root inode should always be a directory
            if is_root_inode:
                check_condition(stat.S_ISDIR(i.mode), "root node should always be a directory")
                is_root_inode = False

            zones = []

            # sanity checks for the zones
            for zone in i.direct_zone_numbers:
                check_condition(zone.number == 0 or zone.number >= self.data.superblock.first_data_zone,
                                "invalid zone number")
                if zone.number != 0:
                    zones.append(zone)

            # check indirect zone data
            check_condition(i.indirect_zone_number.number == 0 or i.indirect_zone_number.number >= self.data.superblock.first_data_zone,
                               "invalid zone number")

            if i.indirect_zone_number.zone_data is not None:
                for zone in i.indirect_zone_number.zone_data:
                    check_condition(zone.number == 0 or zone.number >= self.data.superblock.first_data_zone,
                                       "invalid zone number")
                    if zone.number != 0:
                        zones.append(zone)

            # check double indirect zone data
            check_condition(i.double_indirect_zone_number.number == 0 or i.double_indirect_zone_number.number >= self.data.superblock.first_data_zone,
                               "invalid zone number")

            if i.double_indirect_zone_number.zone_data is not None:
                for zone in i.double_indirect_zone_number.zone_data:
                    check_condition(zone.number == 0 or zone.number >= self.data.superblock.first_data_zone,
                                       "invalid zone number")
                    if zone.zone_data is not None:
                        for double_zone in zone.zone_data:
                            check_condition(double_zone.number == 0 or double_zone.number >= self.data.superblock.first_data_zone,
                                               "invalid zone number")
                            if double_zone.number != 0:
                                zones.append(double_zone)

            # sanity checks for inodes
            if stat.S_ISDIR(i.mode):
                current_directory = self.inode_to_name[inode_counter]
                for z in zones:
                    for r in range(0, len(z.zone_data.data)//32):
                        inode_bytes = z.zone_data.data[r*32:r*32+32]
                        inodenr = int.from_bytes(inode_bytes[:2], byteorder='little')

                        if inodenr == 0:
                            continue

                        # invalid inodes with a higher number than the total
                        # amount of inodes
                        check_condition(inodenr <= self.data.superblock.num_inodes,
                                        "inode number larger than total amount of inodes")

                        try:
                            inode_name = inode_bytes[2:].split(b'\x00', 1)[0].decode()
                        except:
                            # TODO: what to do in this case?
                            continue

                        if inode_name not in ['.', '..']:
                            self.inode_to_name[inodenr] = current_directory / inode_name
            elif stat.S_ISREG(i.mode):
                check_condition(len(zones) != 0, "no valid zones found")

            inode_counter += 1
        check_condition(not is_root_inode, "no valid root inode found")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.superblock.num_zones * self.data.block_size

    def unpack(self, meta_directory):
        unpacked_files = []

        # walk all the inodes, the root inode is always 1
        inode_counter = 1
        for i in self.data.inodes:
            if i.mode == 0:
                continue

            zones = []

            # sanity checks for the zones
            for zone in i.direct_zone_numbers:
                if zone.number != 0:
                    zones.append(zone)

            if i.indirect_zone_number.zone_data is not None:
                for zone in i.indirect_zone_number.zone_data:
                    if zone.number != 0:
                        zones.append(zone)

            if i.double_indirect_zone_number.zone_data is not None:
                for zone in i.double_indirect_zone_number.zone_data:
                    if zone.zone_data is not None:
                        for double_zone in zone.zone_data:
                            if double_zone.number != 0:
                                zones.append(double_zone)

            file_path = self.inode_to_name[inode_counter]

            if stat.S_ISDIR(i.mode):
                current_directory = self.inode_to_name[inode_counter]
                if current_directory != pathlib.Path(''):
                    meta_directory.unpack_directory(file_path)

                for z in zones:
                    for r in range(0, len(z.zone_data.data)//32):
                        inode_bytes = z.zone_data.data[r*32:r*32+32]
                        inodenr = int.from_bytes(inode_bytes[:2], byteorder='little')

                        if inodenr == 0:
                            continue

                        try:
                            inode_name = inode_bytes[2:].split(b'\x00', 1)[0].decode()
                        except:
                            # TODO: what to do in this case?
                            continue

            elif stat.S_ISREG(i.mode):
                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    for z in zones:
                        outfile.write(z.zone_data.data)
                    outfile.truncate(i.size)
                    yield unpacked_md

            elif stat.S_ISLNK(i.mode):
                # process zones to get the target name
                target = ''
                for z in zones:
                    try:
                        target += z.zone_data.data.split(b'\x00', 1)[0].decode()
                    except:
                        target = ''
                        break
                if target != '':
                    meta_directory.unpack_symlink(file_path, target)

            # do not process character devices, block devices, FIFOs and
            # sockets, but possibly record information about them
            elif stat.S_ISCHR(i.mode):
                pass
            elif stat.S_ISBLK(i.mode):
                pass
            elif stat.S_ISFIFO(i.mode):
                pass
            elif stat.S_ISSOCK(i.mode):
                pass
            inode_counter += 1
        return unpacked_files

    labels = ['minix1l', 'filesystem']

    @property
    def metadata(self):
        metadata = {}
        metadata['list'] = {}
        inode_counter = 1
        for i in self.data.inodes:
            if i.mode == 0:
                continue
            metadata['list'][str(self.inode_to_name[inode_counter])] = {
              'uid': i.uid, 'gid': i.gid, 'time': i.time, 'mode': i.mode}
            inode_counter += 1
        return metadata
