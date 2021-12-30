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


import math
import os
import pathlib

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

# UBI (Unsorted Block Image) is not a file system, but it
# is typically used in combination with UBIFS or squashfs,
# so it is lumped in with the rest of the file systems.
#
# http://www.linux-mtd.infradead.org/doc/ubidesign/ubidesign.pdf
#
# Linux kernel source code: drivers/mtd/ubi/ubi-media.h
#
# Extra inspiration from:
#
# https://github.com/nlitsme/ubidump


class UbiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0,  b'UBI#')
    ]
    pretty_name = 'ubi'

    def parse(self):
        # the block size is not known in advance, so just read some
        # data (1 MiB) to see where the next UBI block can be found.
        # After the block size is known the structure is straightforward.
        # blocksize is initially set to 0
        self.blocksize = 0
        readsize = 1048576
        ubifound = False
        file_size = self.fileresult.filesize

        isfirstblock = True

        # store the volume tables from the layout volume per image
        self.volume_tables = {}

        # store the number of layout volumes per image
        layout_volumes_per_image = {}

        # store some info about each block
        self.blocks = {}

        # store which blocks belong to an image
        self.image_to_erase_blocks = {}

        # seek to the start of the UBI block
        # note: the offset is already relative, because OffsetInputFile
        # is used.
        curoffset = 0
        self.infile.seek(curoffset)

        # Now keep processing UBI blocks until no more valid UBI blocks can
        # be found. It could be that multiple images are concatenated. Typically
        # each image should have two layout volumes first, but there are UBI
        # volumes where the layout volumes appear later in the file. These
        # are not yet supported.
        ubiseen = 0
        blockid = 0

        while True:
            if not isfirstblock:
                if curoffset + self.blocksize > file_size:
                    break

            self.infile.seek(curoffset)

            # magic
            checkbytes = self.infile.read(4)
            if checkbytes != b'UBI#':
                break
            unpackedsize = 4

            # UBI version
            checkbytes = self.infile.read(1)
            ubi_version = ord(checkbytes)
            unpackedsize += 1

            # three padding bytes
            checkbytes = self.infile.read(3)
            if checkbytes != b'\x00\x00\x00':
                break
            unpackedsize += 3

            # number of erasures for the block
            checkbytes = self.infile.read(8)
            erase_count = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 8

            # offset of the volume identifier header, relative
            # to the start of the erase block
            checkbytes = self.infile.read(4)
            vid_hdr_offset = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 4

            # volume identifier cannot start inside the
            # current erase block header
            if vid_hdr_offset < 64:
                break

            # offset to data in the erase block, relative
            # to the start of the erase block
            checkbytes = self.infile.read(4)
            data_offset = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 4

            # data offset cannot start inside the current erase block header
            if data_offset < 64:
                break

            # check if the data offset doesn't start in the volume header
            # TODO: extra checks
            if data_offset > vid_hdr_offset:
                if data_offset - vid_hdr_offset < 64:
                    break

            # image sequence
            checkbytes = self.infile.read(4)
            image_sequence = int.from_bytes(checkbytes, byteorder='big')

            # if the image sequence is not known, then this block
            # is the first block of the image. Potentially blocks
            # of different images could be interleaved, but that
            # is just asking for trouble, so assume that doesn't
            # happen.
            if image_sequence not in self.volume_tables:
                isfirstblock = True
            unpackedsize += 4

            # 32 padding bytes
            checkbytes = self.infile.read(32)
            if checkbytes != b'\x00' * 32:
                break
            unpackedsize += 32

            # and finally a header CRC
            checkbytes = self.infile.read(4)
            header_crc = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 4

            # Determine the block size if this is the first block.
            # This is done here to prevent the whole file from
            # being read in its entirety, so do this after quite a few
            # sanity checks.
            if isfirstblock:
                self.blocksize = 0
                self.infile.seek(curoffset)
                while True:
                    checkbytes = self.infile.read(readsize)
                    if checkbytes == b'':
                        # end of the file reached, this cannot be an UBI image
                        break
                    nextubi = checkbytes.find(b'UBI#', 1)
                    if nextubi != -1:
                        self.blocksize += nextubi
                        ubifound = True
                        break
                    self.blocksize += readsize

                if not ubifound:
                    break

                # sanity check: block size has to be a power of 2
                if self.blocksize != pow(2, int(math.log(self.blocksize, 2))):
                    break
                isfirstblock = False

            # extra sanity checks for volume identifier header
            # and data offset. volume identifier header is
            # 64 bytes.
            if curoffset + self.blocksize > file_size:
                break

            if vid_hdr_offset > self.blocksize or data_offset > self.blocksize:
                break

            # jump to the volume identifier and process the data
            self.infile.seek(curoffset + vid_hdr_offset)
            unpackedsize = vid_hdr_offset

            # first the magic
            checkbytes = self.infile.read(4)
            if checkbytes != b'UBI!':
                break
            unpackedsize += 4

            # then the ubi version, should be the same as the previouis one
            checkbytes = self.infile.read(1)
            if ord(checkbytes) != ubi_version:
                break
            unpackedsize += 1

            # volume type, can be 1 (dynamic) or 2 (static)
            checkbytes = self.infile.read(1)
            volumetype = ord(checkbytes)
            if volumetype not in [1, 2]:
                break
            unpackedsize += 1

            # copy flag, skip for now
            checkbytes = self.infile.read(1)
            copyflag = ord(checkbytes)
            unpackedsize += 1

            # compatibility flags
            checkbytes = self.infile.read(1)
            compat = ord(checkbytes)
            unpackedsize += 1

            # volume id
            checkbytes = self.infile.read(4)
            volume_id = int.from_bytes(checkbytes, byteorder='big')
            ubiseen += 1

            if volume_id > 0x7fffefff:
                break

            if image_sequence not in self.volume_tables:
                self.volume_tables[image_sequence] = {}
                layout_volumes_per_image[image_sequence] = 0

            # need layout volume first
            if volume_id != 0x7fffefff and layout_volumes_per_image[image_sequence] == 0:
                break

            # cannot have more than two layout volumes
            if volume_id == 0x7fffefff and layout_volumes_per_image[image_sequence] > 2:
                break
            unpackedsize += 4

            if volume_id == 0x7fffefff:
                # has to be dynamic
                if volumetype != 1:
                    break
                layout_volumes_per_image[image_sequence] += 1

            # logical erase block number. This is basically the number
            # this block has in a volume.
            checkbytes = self.infile.read(4)
            logical_erase_block = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 4

            # 4 bytes of padding
            checkbytes = self.infile.read(4)
            if checkbytes != b'\x00\x00\x00\x00':
                del layout_volumes_per_image[image_sequence]
                break
            unpackedsize += 4

            # data size
            checkbytes = self.infile.read(4)
            data_size = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 4

            # used erase blocks, only used for static volumes, should
            # be 0 for dynamic volumes
            checkbytes = self.infile.read(4)
            used_ebs = int.from_bytes(checkbytes, byteorder='big')
            if volumetype == 1:
                if used_ebs != 0:
                    del layout_volumes_per_image[image_sequence]
                    break
            unpackedsize += 4

            # data pad, skip for now
            self.infile.seek(4, os.SEEK_CUR)
            unpackedsize += 4

            # data crc, skip for now
            self.infile.seek(4, os.SEEK_CUR)
            unpackedsize += 4

            # 4 bytes of padding
            checkbytes = self.infile.read(4)
            if checkbytes != b'\x00\x00\x00\x00':
                del layout_volumes_per_image[image_sequence]
                break
            unpackedsize += 4

            # sequence number
            checkbytes = self.infile.read(8)
            sequence_number = int.from_bytes(checkbytes, byteorder='big')
            unpackedsize += 8

            # 12 bytes of padding
            checkbytes = self.infile.read(12)
            if checkbytes != b'\x00' * 12:
                del layout_volumes_per_image[image_sequence]
                break
            unpackedsize += 12

            # header crc, skip for now
            self.infile.seek(4, os.SEEK_CUR)
            unpackedsize += 4

            # jump to the data offset and process the data. Maximum
            # is 128, but it depends on how much data is actually available.
            self.infile.seek(curoffset + data_offset)
            unpackedsize = data_offset

            # read the volume tables from the first layout volume
            if volume_id == 0x7fffefff:
                if layout_volumes_per_image[image_sequence] == 2:
                    # skip the layout volume copy
                    curoffset += self.blocksize
                    blockid += 1
                    continue

                # each volume table entry is 172 bytes, and
                # the amount read depends on the size of the
                # erase block.
                max_volume_tables = (self.blocksize - unpackedsize)//172
                volume_table_count = min(128, max_volume_tables)
                broken_volume_table = False
                for volume_table in range(0, volume_table_count):
                    # reserved physical erase blocks
                    checkbytes = self.infile.read(4)
                    phys_erase_blocks = int.from_bytes(checkbytes, byteorder='big')
                    unpackedsize += 4

                    # alignment
                    checkbytes = self.infile.read(4)
                    alignment = int.from_bytes(checkbytes, byteorder='big')
                    unpackedsize += 4

                    # data padding
                    checkbytes = self.infile.read(4)
                    data_padding = int.from_bytes(checkbytes, byteorder='big')
                    unpackedsize += 4

                    # volume type
                    checkbytes = self.infile.read(1)
                    volume_type = ord(checkbytes)
                    unpackedsize += 1

                    # update marker
                    checkbytes = self.infile.read(1)
                    update_marker = ord(checkbytes)
                    unpackedsize += 1

                    # volume name length
                    checkbytes = self.infile.read(2)
                    name_length = int.from_bytes(checkbytes, byteorder='big')
                    unpackedsize += 2

                    # volume name
                    checkbytes = self.infile.read(128)
                    try:
                        volume_name = checkbytes.split(b'\x00', 1)[0].decode()
                        if os.path.isabs(volume_name):
                            volume_name = os.path.relpath(volume_name, '/')
                    except UnicodeDecodeError:
                        broken_volume_table = True
                        break
                    if name_length != len(volume_name):
                        broken_volume_table = True
                        break
                    unpackedsize += 128

                    # flags
                    checkbytes = self.infile.read(1)
                    volume_flags = ord(checkbytes)
                    unpackedsize += 1

                    # padding
                    checkbytes = self.infile.read(23)
                    if checkbytes != b'\x00' * 23:
                        broken_volume_table = True
                        break
                    unpackedsize += 23

                    # crc, skip
                    self.infile.seek(4, os.SEEK_CUR)
                    unpackedsize += 4

                    if phys_erase_blocks != 0:
                        self.volume_tables[image_sequence][volume_table] = {'name': volume_name,
                                                       'blocks': phys_erase_blocks,
                                                       'flags': volume_flags,
                                                       'alignment': alignment,
                                                       'padding': data_padding,
                                                       'marker': update_marker,
                                                      }

                if broken_volume_table:
                    del layout_volumes_per_image[image_sequence]
                    break
                curoffset += self.blocksize
            else:
                # store the blocks per image, the first two are always
                # layout volume blocks
                if image_sequence not in self.image_to_erase_blocks:
                    self.image_to_erase_blocks[image_sequence] = [0, 1]
                self.image_to_erase_blocks[image_sequence].append(blockid)
                curoffset += self.blocksize
            if curoffset > file_size:
                break
            self.blocks[blockid] = {'offset': data_offset, 'logical': logical_erase_block}
            blockid += 1

        # sanity checks for actual data
        data_unpacked = False

        # check the data for each image, without writing
        for image_sequence in self.volume_tables:
            image_block_counter = 2
            for vt in sorted(self.volume_tables[image_sequence].keys()):
                if image_sequence not in self.image_to_erase_blocks:
                    continue
                volume_table = self.volume_tables[image_sequence][vt]

                seen_logical = 0
                broken_image = False
                for block in range(image_block_counter, len(self.image_to_erase_blocks[image_sequence])):
                    erase_block = self.image_to_erase_blocks[image_sequence][block]
                    if erase_block not in self.blocks:
                        broken_image = True
                        break
                    if self.blocks[erase_block]['logical'] < seen_logical:
                        image_block_counter = erase_block
                        break
                    seen_logical = self.blocks[erase_block]['logical']
                    readoffset = erase_block * self.blocksize + self.blocks[block]['offset']
                    blockreadsize = self.blocksize - self.blocks[erase_block]['offset']
                    unpackedsize = max(unpackedsize, readoffset + blockreadsize)

                check_condition(not broken_image, "not a valid UBI image")
                data_unpacked = True

        check_condition(data_unpacked, "no data could be unpacked")
        self.unpacked_size = unpackedsize

    def unpack(self):
        unpacked_files = []

        # write the data for each image
        for image_sequence in self.volume_tables:
            image_block_counter = 2
            for vt in sorted(self.volume_tables[image_sequence].keys()):
                if image_sequence not in self.image_to_erase_blocks:
                    continue
                volume_table = self.volume_tables[image_sequence][vt]

                # open the output file
                # TODO: check if there are any duplicate names inside an image
                outfile_rel = self.rel_unpack_dir / ("image-%d" % image_sequence) / volume_table['name']
                outfile_full = self.scan_environment.unpack_path(outfile_rel)
                os.makedirs(os.path.dirname(outfile_full), exist_ok=True)
                outfile = open(outfile_full, 'wb')

                seen_logical = 0
                for block in range(image_block_counter, len(self.image_to_erase_blocks[image_sequence])):
                    erase_block = self.image_to_erase_blocks[image_sequence][block]
                    if erase_block not in self.blocks:
                        break
                    if self.blocks[erase_block]['logical'] < seen_logical:
                        image_block_counter = erase_block
                        break
                    seen_logical = self.blocks[erase_block]['logical']
                    readoffset = erase_block * self.blocksize + self.blocks[block]['offset']
                    blockreadsize = self.blocksize - self.blocks[erase_block]['offset']
                    os.sendfile(outfile.fileno(), self.infile.fileno(), self.offset + readoffset, blockreadsize)
                outfile.close()

                fr = FileResult(self.fileresult, outfile_rel, set())
                unpacked_files.append(fr)

        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ubi']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
