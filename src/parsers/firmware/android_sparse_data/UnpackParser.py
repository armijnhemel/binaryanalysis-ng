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

# Some Android firmware updates are distributed as sparse data images.
# Given a data image and a transfer list data on an Android device is
# block wise added, replaced, erased, or zeroed.
#
# The Android sparse data image format is documented in the Android
# source code tree:
#
# https://android.googlesource.com/platform/bootable/recovery/+/4f81130039f6a312eba2027b3594a2be282f6b3a/updater/blockimg.cpp#1980
#
# Test files can be downloaded from LineageOS, for example:
#
# lineage-14.1-20180410-nightly-FP2-signed.zip
#
# Note: this is different to the Android sparse image format.


import os
import pathlib

import brotli

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class AndroidSparseDataUnpackParser(UnpackParser):
    extensions = ['.new.dat', 'new.dat.br']
    signatures = []
    pretty_name = 'androidsparsedata'

    def parse(self):
        transferfile = pathlib.Path(self.infile.name[:-8] + ".transfer.list")
        check_condition(transferfile.exists(), "transfer list not found")

        # open the transfer list in text mode, not in binary mode
        transferlist = open(transferfile, 'r')
        transferlistlines = list(map(lambda x: x.strip(), transferlist.readlines()))
        transferlist.close()

        check_condition(len(transferlistlines) >= 4, "not enough entries in transer list")

        # first line is the version number, see comment here:
        # https://android.googlesource.com/platform/bootable/recovery/+/master/updater/blockimg.cpp#1628
        try:
            version_number = int(transferlistlines[0])
        except ValueError as e:
            raise UnpackParserException(e.args)

        check_condition(version_number <= 4, "invalid version number")
        check_condition(version_number >= 2, "only transfer list version 2-4 supported")

        # the next line is the amount of blocks (1 block is 4096 bytes)
        # that will be copied to the output. This does not necessarily
        # anything about the size of the output file as it might not include
        # the blocks such as erase or zero, so it can be safely ignored.
        try:
            output_blocks = int(transferlistlines[1])
        except ValueError as e:
            raise UnpackParserException(e.args)

        # then two lines related to stash entries which are only used by
        # Android during updates to prevent flash space from overflowing,
        # so can safely be ignored here.
        try:
            stash_needed = int(transferlistlines[2])
        except ValueError as e:
            raise UnpackParserException(e.args)

        try:
            max_stash = int(transferlistlines[2])
        except ValueError as e:
            raise UnpackParserException(e.args)

        # a list of commands recognized
        valid_transfer_commands = set(['new', 'zero', 'erase', 'free', 'stash'])

        self.transfercommands = []

        # store the maximum block number
        self.maxblock = 0

        # then parse the rest of the lines to see if they are valid
        for l in transferlistlines[4:]:
            transfersplit = l.split(' ')
            check_condition(len(transfersplit) == 2,
                            "invalid line in transfer list")
            (transfercommand, transferblocks) = transfersplit
            check_condition(transfercommand in valid_transfer_commands,
                            "unsupported command in transfer list")
            transferblockssplit = transferblocks.split(',')
            check_condition(len(transferblockssplit) % 2 != 0,
                            "invalid transfer block list in transfer list")

            # first entry is the number of blocks on the rest of line
            try:
                transferblockcount = int(transferblockssplit[0])
            except ValueError as e:
                raise UnpackParserException(e.args)

            check_condition(transferblockcount == len(transferblockssplit[1:]),
                            "invalid transfer block list in transfer list")

            # then check the rest of the numbers
            try:
                blocks = []
                for b in transferblockssplit[1:]:
                    blocknr = int(b)
                    blocks.append(blocknr)
                    self.maxblock = max(self.maxblock, blocknr)
            except ValueError as e:
                raise UnpackParserException(e.args)

            # store the transfer commands
            self.transfercommands.append((transfercommand, blocks))

    def calculate_unpacked_size(self):
        self.unpacked_size = self.fileresult.filesize

    def unpack(self):
        unpacked_files = []
        # block size is set to 4096 in the Android source code
        blocksize = 4096

        unpackdir_full = self.scan_environment.unpack_path(self.rel_unpack_dir)

        # cut the extension '.new.dat' from the file name unless the file
        # name is the extension (as there would be a zero length name).
        if len(self.fileresult.filename.stem) == 0:
            file_path = pathlib.Path("unpacked_from_android_sparse_data")
        else:
            file_path = pathlib.Path(self.fileresult.filename.stem)
            if file_path in ['.', '..']:
                file_path = pathlib.Path("unpacked_from_android_sparse_data")

        outfile_rel = self.rel_unpack_dir / file_path
        outfile_full = self.scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')

        # make sure that the target file is large enough.
        # On Linux truncate() will zero fill the targetfile.
        outfile.truncate(self.maxblock*blocksize)

        # then seek to the beginning of the target file
        outfile.seek(0)

        self.infile.seek(0)

        # then process all the commands. "zero" is not interesting as
        # the underlying file has already been zero filled.
        # erase is not very interesting either.
        for c in self.transfercommands:
            (transfercommand, blocks) = c
            if transfercommand == 'new':
                for b in range(0, len(blocks), 2):
                    outfile.seek(blocks[b]*blocksize)
                    os.sendfile(outfile.fileno(), self.infile.fileno(), None, (blocks[b+1] - blocks[b]) * blocksize)
            else:
                pass

        outfile.close()
        fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set())
        unpacked_files.append(fr)

        return unpacked_files

    def carve(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['android', 'android sparse data']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
