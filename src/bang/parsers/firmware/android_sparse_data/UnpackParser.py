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
import sys
import tempfile
import time

import brotli

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class AndroidSparseDataUnpackParser(UnpackParser):
    extensions = ['.new.dat', 'new.dat.br']
    signatures = []
    pretty_name = 'androidsparsedata'
    MAX_WAITS = 10
    SLEEP_TIME = 1

    def parse(self):
        self.is_brotli = False
        if self.infile.name.endswith('.new.dat'):
            transferfile = pathlib.Path(self.infile.name[:-8] + ".transfer.list")
            patchfile = pathlib.Path(self.infile.name[:-8] + ".patch.dat")
        elif self.infile.name.endswith('.new.dat.br'):
            self.is_brotli = True
            transferfile = pathlib.Path(self.infile.name[:-11] + ".transfer.list")
            patchfile = pathlib.Path(self.infile.name[:-11] + ".patch.dat")
        check_condition(transferfile.exists(), "transfer list not found")

        if patchfile.exists():
            check_condition(patchfile.stat().st_size == 0, "patches not supported")

        if transferfile.stat().st_size == 0:
            ctr = 0
            while True:
                if transferfile.stat().st_size != 0:
                    break
                check_condition(ctr <= self.MAX_WAITS, "required file .transferlist empty (not yielded quickly enough?)")
                time.sleep(self.SLEEP_TIME)
                ctr += 1

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

        # Brotli compression requires that the file is first decompressed
        # before processing.
        if self.is_brotli:
            chunksize = 1000000
            checkbuffer = bytearray(900000)

            decompressor = brotli.Decompressor()

            self.temporary_file = tempfile.mkstemp(dir=self.configuration.temporary_directory)

            bytesread = self.infile.readinto(checkbuffer)
            buf = memoryview(checkbuffer[:bytesread])
            while bytesread != 0:
                try:
                    data = decompressor.process(buf)
                    os.write(self.temporary_file[0], data)
                    os.fsync(self.temporary_file[0])
                except EOFError as e:
                    break
                except Exception as e:
                    # no data could be successfully unpacked
                    os.fdopen(self.temporary_file[0]).close()
                    os.unlink(self.temporary_file[1])
                    raise UnpackParserException(e.args)

                if decompressor.is_finished():
                    # there is no more compressed data
                    break
                bytesread = self.infile.readinto(checkbuffer)
                buf = memoryview(checkbuffer[:bytesread])
            if not decompressor.is_finished():
                os.fdopen(self.temporary_file[0]).close()
                os.unlink(self.temporary_file[1])
                raise UnpackParserException("brotli data not complete")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

    def unpack(self, meta_directory):
        # block size is set to 4096 in the Android source code
        blocksize = 4096

        # cut the extension '.new.dat' from the file name unless the file
        # name is the extension (as there would be a zero length name).

        if self.is_brotli:
            file_path = pathlib.Path(meta_directory.file_path.name[:-11])
        else:
            file_path = pathlib.Path(meta_directory.file_path.name[:-8])

        if file_path in ['.', '..']:
            # invalid path, so make anonymous
            file_path = pathlib.Path("unpacked_from_android_sparse_data")
        elif file_path == '':
            # invalid path, so make anonymous
            file_path = pathlib.Path("unpacked_from_android_sparse_data")

        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
            # make sure that the target file is large enough.
            # On Linux truncate() will zero fill the targetfile.
            outfile.truncate(self.maxblock*blocksize)

            # then seek to the beginning of the target file
            outfile.seek(0)

            # keep the offset for the position in the input file
            # although this should be done automatically when using
            # sendfile() (and this was working correctly in the old parser)
            # it seems that with context managers sometimes the file
            # pointer is moved forwards 4096 bytes.
            infile_offset = 0

            # then process all the commands. "zero" is not interesting as
            # the underlying file has already been zero filled.
            # erase is not very interesting either.
            for c in self.transfercommands:
                (transfercommand, blocks) = c
                if transfercommand == 'new':
                    for b in range(0, len(blocks), 2):
                        outfile.seek(blocks[b]*blocksize)
                        if self.is_brotli:
                            os.sendfile(outfile.fileno(), self.temporary_file[0], infile_offset, (blocks[b+1] - blocks[b]) * blocksize)
                        else:
                            os.sendfile(outfile.fileno(), self.infile.fileno(), infile_offset, (blocks[b+1] - blocks[b]) * blocksize)
                        infile_offset += (blocks[b+1] - blocks[b]) * blocksize
                else:
                    pass
            yield unpacked_md

        if self.is_brotli:
            os.fdopen(self.temporary_file[0]).close()
            os.unlink(self.temporary_file[1])

    labels = ['android', 'android sparse data']
    metadata = {}
