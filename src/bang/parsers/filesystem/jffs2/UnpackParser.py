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

# JFFS2 https://en.wikipedia.org/wiki/JFFS2
# JFFS2 is a file system that was used on earlier embedded Linux
# system, although it is no longer the first choice for modern systems,
# where for example UBI/UBIFS are chosen.

import lzma
import os
import pathlib
import zlib

import lzo

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import jffs2

# The mtd-utils code defines more types of "compression"
# than supported by mkfs.jffs2
# LZMA compression is available as a patch from OpenWrt.
# LZMA settings from OpenWrt's patch
LZMA_DICT_SIZE = 0x2000
LZMA_PB = 0
LZMA_LP = 0
LZMA_LC = 0


class Jffs2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x85\x19'),
        (0, b'\x19\x85')
    ]
    pretty_name = 'jffs2'

    def parse(self):
        # parse the first inode to see if it is a little endian
        # or big endian file system. The first inode is *always*
        # a valid inode, not a dirty inode.
        try:
            root_inode = jffs2.Jffs2.from_io(self.infile)
        except (ValidationFailedError, ValueError, EOFError) as e:
            raise UnpackParserException(e.args)

        # store endianness, as it is needed in some cases (dirty nodes)
        self.bigendian = False
        byteorder = 'little'
        if root_inode.magic == jffs2.Jffs2.Magic.be:
            self.bigendian = True
            byteorder = 'big'

        # keep a list of inodes to file names
        # the root inode (1) always has ''
        inode_to_filename = {}
        inode_to_filename[1] = pathlib.Path('')

        data_unpacked = False

        # keep track of which nodes have already been seen. This is to
        # detect if multiple JFFS2 file systems have been concatenated.
        # Also store the version, as inodes could have been reused in the
        # case of hardlinks.
        inodes_seen_version = set()
        parent_inodes_seen = set()

        # keep a mapping of inodes to last written position in
        # the file.
        inode_to_write_offset = {}

        # a mapping of inodes to open files
        inode_to_open_files = {}
        current_inode = None

        root_seen = False

        # reset the file pointer to the start of the file system and read all
        # the inodes. It isn't necessarily known in advance how many inodes
        # there will be, so process all the files until either the end
        # of the file is reached, a new file system is started, or the file
        # system ends.
        self.infile.seek(0)

        prev_is_padding = False
        while True:
            cur_offset = self.infile.tell()

            # stop processing if the end of the file is reached
            if self.infile.tell() == self.infile.size:
                break

            # read the first two bytes to see if it is a normal
            # node, a dirty node or empty space. This cannot be
            # nicely captured in Kaitai Struct.
            buf = self.infile.read(2)
            if len(buf) != 2:
                break

            # first check if the inode magic is valid: big endian
            # and big endian cannot be mixed.
            if self.bigendian:
                if buf not in [b'\x19\x85', b'\x00\x00', b'\xff\xff']:
                    break
            else:
                if buf not in [b'\x85\x19', b'\x00\x00', b'\xff\xff']:
                    break

            if buf == b'\x00\x00':
                # dirty nodes
                node_magic_type = 'dirty'
            elif buf == b'\xff\xff':
                # empty space
                # read the next two bytes to see if they are empty as well
                buf = self.infile.read(2)
                if buf != b'\xff\xff':
                    break
                continue
            else:
                node_magic_type = 'normal'

            # skip dirty nodes. Some manual parsing is needed here. As from
            # the magic it isn't clear which endianness is used it needs to
            # be taken from the context
            if node_magic_type == 'dirty':
                self.infile.seek(2, os.SEEK_CUR)
                buf = self.infile.read(4)
                if len(buf) != 4:
                    break

                len_inode = int.from_bytes(buf, byteorder=byteorder)
                if len_inode == 0:
                    break
                if cur_offset + len_inode > self.infile.size:
                    break

                # skip the dirty data
                self.infile.seek(cur_offset + len_inode)

                unpackedsize = self.infile.tell()
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize % 4)
                    self.infile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = self.infile.tell()
                continue

            # reset the file pointer and parse with Kaitai Struct
            self.infile.seek(cur_offset)

            try:
                jffs2_inode = jffs2.Jffs2.from_io(self.infile)
            except (ValidationFailedError , ValueError, EOFError) as e:
                break

            if jffs2_inode.magic != root_inode.magic and jffs2_inode.magic != jffs2.Jffs2.Magic.dirty:
                break

            # check if the inode type is actually valid
            # or perhaps contains padding.
            if type(jffs2_inode.header.inode_type) == int:
                if jffs2_inode.header.inode_type == 0:
                    if prev_is_padding:
                        break
                    # due to page alignments there might
                    # be extra NULL bytes
                    if (cur_offset + 4) % 4096 != 0:
                        ofs = self.infile.tell()
                        bytes_to_read = 4096 - ((cur_offset + 4)%4096)
                        buf = self.infile.read(bytes_to_read)
                        if buf != b'\x00' * bytes_to_read:
                            self.infile.seek(ofs)
                            break
                else:
                    break
                prev_is_padding = True
                continue

            prev_is_padding = False

            # Verify the header CRC of the first 8 bytes in the node
            # The checksum is not the same as the CRC32 algorithm from
            # zlib, and it is explained here:
            #
            # http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
            #
            # The checksum varies slightly from the one in the zlib modules
            # as explained here:
            #
            # http://www.infradead.org/pipermail/linux-mtd/2003-February/006910.html
            #
            # specific implementation for computing checksum grabbed from
            # MIT licensed script found at:
            #
            # https://github.com/sviehb/jefferson/blob/master/src/scripts/jefferson
            stored_offset = self.infile.tell()
            self.infile.seek(cur_offset)
            crc_bytes = self.infile.read(8)
            self.infile.seek(stored_offset)

            if jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.dirent or \
                jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.inode:
                computedcrc = (zlib.crc32(crc_bytes, -1) ^ -1) & 0xffffffff
                if not computedcrc == jffs2_inode.data.header_crc:
                    break

                inode_number = jffs2_inode.data.inode_number

            # process directory entries
            if jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.dirent:
                parent_inodes_seen.add(jffs2_inode.data.parent_inode)

                # skip unlinked inodes
                if inode_number == 0:
                    # first go back to the old offset, then skip
                    # the entire inode
                    self.infile.seek(cur_offset + jffs2_inode.header.len_inode)
                    unpackedsize = self.infile.tell()
                    if unpackedsize % 4 != 0:
                        paddingbytes = 4 - (unpackedsize % 4)
                        self.infile.seek(paddingbytes, os.SEEK_CUR)
                        unpackedsize = self.infile.tell()
                    continue

                # cannot have duplicate inodes
                if (inode_number, jffs2_inode.data.inode_version) in inodes_seen_version:
                    break

                inodes_seen_version.add((inode_number, jffs2_inode.data.inode_version))

                # the name of the node
                try:
                    inode_name = jffs2_inode.data.name.decode()
                except UnicodeDecodeError:
                    break

                # compute the CRC of the name
                computedcrc = (zlib.crc32(jffs2_inode.data.name, -1) ^ -1) & 0xffffffff
                if jffs2_inode.data.name_crc != computedcrc:
                    break

                # now add the name to the inode to filename mapping
                if jffs2_inode.data.parent_inode in inode_to_filename:
                    inode_to_filename[inode_number] = inode_to_filename[jffs2_inode.data.parent_inode] / inode_name

            elif jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.inode:
                # first check if a file name for this inode is known
                if inode_number not in inode_to_filename:
                    break

                # skip unlinked inodes
                if inode_number == 0:
                    # first go back to the old offset, then skip
                    # the entire inode
                    self.infile.seek(cur_offset + jffs2_inode.header.len_inode)
                    unpackedsize = self.infile.tell()
                    if unpackedsize % 4 != 0:
                        paddingbytes = 4 - (unpackedsize % 4)
                        self.infile.seek(paddingbytes, os.SEEK_CUR)
                        unpackedsize = self.infile.tell()
                    continue

                filemode = jffs2_inode.data.file_mode

                if filemode == jffs2.Jffs2.Modes.socket:
                    # keep track of whatever is in the file and report
                    pass
                elif filemode == jffs2.Jffs2.Modes.directory:
                    # create directories, but skip them otherwise
                    self.infile.seek(cur_offset + jffs2_inode.header.len_inode)
                    data_unpacked = True
                    continue
                elif filemode == jffs2.Jffs2.Modes.link:
                    try:
                        symlink = jffs2_inode.data.body.data.decode()
                        data_unpacked = True
                    except UnicodeDecodeError:
                        break
                elif filemode == jffs2.Jffs2.Modes.regular:
                    writeoffset = jffs2_inode.data.body.ofs_write

                    if writeoffset == 0:
                        if inode_number in inode_to_write_offset:
                            break
                        if inode_number in inode_to_open_files:
                            break

                        # store a reference as if there was an open file
                        inode_to_open_files[inode_number] = {}
                        current_inode = inode_number
                    else:
                        if writeoffset != inode_to_write_offset[inode_number]:
                            break
                        if inode_number not in inode_to_open_files:
                            break

                    # Check the compression that's used as it could be that
                    # for a file compressed and uncompressed nodes are mixed
                    # in case the node cannot be compressed efficiently
                    # and the compressed data would be larger than the
                    # original data.
                    decompressed_size = jffs2_inode.data.body.len_decompressed

                    if jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.no_compression:
                        # the data is not compressed, so can be written
                        # to the output file immediately
                        data_unpacked = True
                    elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.zlib:
                        # the data is zlib compressed, so first decompress
                        # before writing
                        try:
                            zlib.decompress(jffs2_inode.data.body.data)
                            data_unpacked = True
                        except Exception as e:
                            break
                    elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.lzma:
                        # The data is LZMA compressed, so create a
                        # LZMA decompressor with custom filter, as the data
                        # is stored without LZMA headers.
                        jffs_filters = [{'id': lzma.FILTER_LZMA1,
                                         'dict_size': LZMA_DICT_SIZE,
                                         'lc': LZMA_LC, 'lp': LZMA_LP,
                                         'pb': LZMA_PB}]

                        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=jffs_filters)

                        try:
                            decompressor.decompress(jffs2_inode.data.body.data)
                            data_unpacked = True
                        except Exception as e:
                            break
                    elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.rtime:
                        # From: https://github.com/sviehb/jefferson/blob/master/src/jefferson/rtime.py
                        # First initialize the positions, set to 0
                        positions = [0] * 256

                        # create a bytearray, set everything to 0
                        data_out = bytearray([0] * decompressed_size)

                        # create counters
                        outpos = 0
                        pos = 0

                        # process all the bytes
                        while outpos < decompressed_size:
                            value = jffs2_inode.data.body.data[pos]
                            pos += 1
                            data_out[outpos] = value
                            outpos += 1
                            repeat = jffs2_inode.data.body.data[pos]
                            pos += 1

                            backoffs = positions[value]
                            positions[value] = outpos
                            if repeat:
                                if backoffs + repeat >= outpos:
                                    while repeat:
                                        data_out[outpos] = data_out[backoffs]
                                        outpos += 1
                                        backoffs += 1
                                        repeat -= 1
                                else:
                                    data_out[outpos : outpos + repeat] = data_out[
                                        backoffs : backoffs + repeat
                                    ]
                                    outpos += repeat
                    elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.lzo:
                        try:
                            lzo.decompress(jffs2_inode.data.body.data, False, jffs2_inode.data.body.len_decompressed)
                        except:
                            raise UnpackParserException("invalid lzo compressed data")
                    else:
                        break

                    # record how much data was read and use for sanity checks
                    inode_to_write_offset[inode_number] = writeoffset + decompressed_size

            unpackedsize = self.infile.tell()
            if unpackedsize % 4 != 0:
                paddingbytes = 4 - (unpackedsize % 4)
                self.infile.seek(paddingbytes, os.SEEK_CUR)
                unpackedsize = self.infile.tell()

        check_condition(data_unpacked, "no data unpacked")
        check_condition(1 in parent_inodes_seen, "no valid root file node")
        self.infile.seek(cur_offset)
        self.unpacked_size = cur_offset

    # For unpacking data only the directory entry and regular inode
    # will be considered.
    def unpack(self, meta_directory):
        unpacked_mds = {}

        inode_to_filename = {}
        inode_to_filename[1] = pathlib.Path('')
        parent_inodes_seen = set()
        inode_to_write_offset = {}
        current_inode = None

        # reset the file pointer to the start of the file system and read all
        # the inodes again, but now for unpacking.
        self.infile.seek(0)

        prev_is_padding = False
        while True:
            cur_offset = self.infile.tell()

            # stop processing as soon as the end of the unpacked data is reached
            if self.infile.tell() == self.unpacked_size:
                break
            buf = self.infile.read(2)
            if len(buf) != 2:
                break

            if buf == b'\x00\x00':
                # dirty nodes
                node_magic_type = 'dirty'
            elif buf == b'\xff\xff':
                # empty space
                # read the next two bytes to see if they are empty as well
                buf = self.infile.read(2)
                if buf != b'\xff\xff':
                    break
                continue
            else:
                node_magic_type = 'normal'

            # skip dirty nodes. Some manual parsing is needed here. As from
            # the magic it isn't clear which endianness is used it needs to
            # be taken from the context
            if node_magic_type == 'dirty':
                self.infile.seek(2, os.SEEK_CUR)
                buf = self.infile.read(4)
                if len(buf) != 4:
                    break

                len_inode = int.from_bytes(buf, byteorder=byteorder)
                if cur_offset + len_inode > self.infile.size:
                    break

                # skip the dirty data
                self.infile.seek(cur_offset + len_inode)

                unpackedsize = self.infile.tell()
                if unpackedsize % 4 != 0:
                    paddingbytes = 4 - (unpackedsize % 4)
                    self.infile.seek(paddingbytes, os.SEEK_CUR)
                    unpackedsize = self.infile.tell()
                continue

            # reset the file pointer and parse with Kaitai Struct
            self.infile.seek(cur_offset)

            jffs2_inode = jffs2.Jffs2.from_io(self.infile)

            # check if the inode type is actually valid
            # or perhaps contains padding.
            if type(jffs2_inode.header.inode_type) == int:
                if jffs2_inode.header.inode_type == 0:
                    if prev_is_padding:
                        break
                    # due to page alignments there might
                    # be extra NULL bytes
                    if (cur_offset + 4) % 4096 != 0:
                        ofs = self.infile.tell()
                        bytes_to_read = 4096 - ((cur_offset + 4)%4096)
                        buf = self.infile.read(bytes_to_read)
                        if buf != b'\x00' * bytes_to_read:
                            self.infile.seek(ofs)
                            break
                else:
                    break
                prev_is_padding = True
                continue

            prev_is_padding = False

            # process directory entries
            if jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.dirent:
                inode_number = jffs2_inode.data.inode_number

                parent_inodes_seen.add(jffs2_inode.data.parent_inode)

                # skip unlinked inodes
                if inode_number == 0:
                    # first go back to the old offset, then skip
                    # the entire inode
                    self.infile.seek(cur_offset + jffs2_inode.header.len_inode)
                    unpackedsize = self.infile.tell()
                    if unpackedsize % 4 != 0:
                        paddingbytes = 4 - (unpackedsize % 4)
                        self.infile.seek(paddingbytes, os.SEEK_CUR)
                        unpackedsize = self.infile.tell()
                    continue

                inode_name = jffs2_inode.data.name.decode()

                # process any possible hard links
                if inode_number in inode_to_filename:
                    # the inode number is already known, meaning
                    # that this should be a hard link
                    target = pathlib.Path(inode_name)
                    file_path = pathlib.Path(inode_to_filename[inode_number])
                    meta_directory.unpack_hardlink(target, file_path)

                # now add the name to the inode to filename mapping
                if jffs2_inode.data.parent_inode in inode_to_filename:
                    inode_to_filename[inode_number] = inode_to_filename[jffs2_inode.data.parent_inode] / inode_name

            elif jffs2_inode.header.inode_type == jffs2.Jffs2.InodeType.inode:
                inode_number = jffs2_inode.data.inode_number

                # first check if a file name for this inode is known
                if inode_number not in inode_to_filename:
                    break

                # first check if a file name for this inode is known
                if inode_number not in inode_to_filename:
                    break

                file_path = pathlib.Path(inode_to_filename[inode_number])

                # skip unlinked inodes
                if inode_number == 0:
                    # first go back to the old offset, then skip
                    # the entire inode
                    self.infile.seek(cur_offset + inode_size)
                    unpackedsize = self.infile.tell()
                    if unpackedsize % 4 != 0:
                        paddingbytes = 4 - (unpackedsize % 4)
                        self.infile.seek(paddingbytes, os.SEEK_CUR)
                        unpackedsize = self.infile.tell()
                    continue

                filemode = jffs2_inode.data.file_mode

                if filemode == jffs2.Jffs2.Modes.socket:
                    # keep track of whatever is in the file and report
                    pass
                elif filemode == jffs2.Jffs2.Modes.directory:
                    # create directories, but skip them otherwise
                    meta_directory.unpack_directory(file_path)
                    continue
                elif filemode == jffs2.Jffs2.Modes.link:
                    target = jffs2_inode.data.body.data.decode()
                    meta_directory.unpack_symlink(file_path, target)
                elif filemode == jffs2.Jffs2.Modes.regular:
                    writeoffset = jffs2_inode.data.body.ofs_write

                    if writeoffset == 0:
                        if inode_number in inode_to_write_offset:
                            break
                        if inode_number in unpacked_mds:
                            break

                        # write a stub file
                        # empty file
                        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                            unpacked_mds[inode_number] = unpacked_md

                        current_inode = inode_number
                    else:
                        if writeoffset != inode_to_write_offset[inode_number]:
                            break
                        if inode_number not in unpacked_mds:
                            break

                    decompressed_size = jffs2_inode.data.body.len_decompressed

                    unpacked_md = unpacked_mds[inode_number]
                    with open(unpacked_md.abs_file_path, 'ab') as outfile:
                        # Check the compression that's used as it could be that
                        # for a file compressed and uncompressed nodes are mixed
                        # in case the node cannot be compressed efficiently
                        # and the compressed data would be larger than the
                        # original data.
                        if jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.no_compression:
                            # the data is not compressed, so can be written
                            # to the output file immediately
                            outfile.write(jffs2_inode.data.body.data)
                        elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.zlib:
                            # the data is zlib compressed, so first decompress
                            # before writing
                            uncompressed_data = zlib.decompress(jffs2_inode.data.body.data)
                            if len(uncompressed_data) > decompressed_size:
                                outfile.write(uncompressed_data[:decompressed_size])
                            else:
                                outfile.write(uncompressed_data)
                        elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.lzma:
                            # The data is LZMA compressed, so create a
                            # LZMA decompressor with custom filter, as the data
                            # is stored without LZMA headers.
                            jffs_filters = [{'id': lzma.FILTER_LZMA1,
                                             'dict_size': LZMA_DICT_SIZE,
                                             'lc': LZMA_LC, 'lp': LZMA_LP,
                                             'pb': LZMA_PB}]

                            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=jffs_filters)
                            uncompressed_data = decompressor.decompress(jffs2_inode.data.body.data)
                            if len(uncompressed_data) > decompressed_size:
                                outfile.write(uncompressed_data[:decompressed_size])
                            else:
                                outfile.write(uncompressed_data)
                        elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.rtime:
                            # From: https://github.com/sviehb/jefferson/blob/master/src/jefferson/rtime.py
                            # First initialize the positions, set to 0
                            positions = [0] * 256

                            # create a bytearray, set everything to 0
                            data_out = bytearray([0] * decompressed_size)

                            # create counters
                            outpos = 0
                            pos = 0

                            # process all the bytes
                            while outpos < decompressed_size:
                                value = jffs2_inode.data.body.data[pos]
                                pos += 1
                                data_out[outpos] = value
                                outpos += 1
                                repeat = jffs2_inode.data.body.data[pos]
                                pos += 1

                                backoffs = positions[value]
                                positions[value] = outpos
                                if repeat:
                                    if backoffs + repeat >= outpos:
                                        while repeat:
                                            data_out[outpos] = data_out[backoffs]
                                            outpos += 1
                                            backoffs += 1
                                            repeat -= 1
                                    else:
                                        data_out[outpos : outpos + repeat] = data_out[
                                            backoffs : backoffs + repeat
                                        ]
                                        outpos += repeat
                            outfile.write(data_out)
                        elif jffs2_inode.data.body.compression == jffs2.Jffs2.Compression.lzo:
                            outfile.write(lzo.decompress(jffs2_inode.data.body.data, False, decompressed_size))
                        else:
                            break

                        # flush any remaining data
                        inode_to_write_offset[inode_number] = writeoffset + decompressed_size
                        outfile.flush()

                        # unsure what to do here now
                        pass

            unpackedsize = self.infile.tell()
            if unpackedsize % 4 != 0:
                paddingbytes = 4 - (unpackedsize % 4)
                self.infile.seek(paddingbytes, os.SEEK_CUR)
                unpackedsize = self.infile.tell()

        for unpacked_md in unpacked_mds.values():
            yield unpacked_md

    labels = ['jffs2', 'filesystem']
    metadata = {}
