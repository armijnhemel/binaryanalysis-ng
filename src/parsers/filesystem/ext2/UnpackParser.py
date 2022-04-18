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
import math
import os
import shutil
import subprocess
import tempfile
import uuid

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_ext2

from . import ext2

class Ext2UnpackParser(WrappedUnpackParser):
#class Ext2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x438,  b'\x53\xef')
    ]
    pretty_name = 'ext2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ext2(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        check_condition(shutil.which('e2ls') is not None, "e2ls program not found")
        check_condition(shutil.which('e2cp') is not None, "e2cp program not found")
        check_condition(shutil.which('tune2fs') is not None, "tune2fs program not found")

        self.infile.seek(1024)

        # parse the superblock using kaitai struct
        try:
            self.superblock = ext2.Ext2.SuperBlockStruct.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.superblock.block_size * self.superblock.blocks_count <= self.fileresult.filesize,
                        "declared file system size larger than file size")

        # TODO: does this have to be math.ceil()?
        block_groups = math.ceil(self.superblock.blocks_count/self.superblock.blocks_per_group)
        self.unpacked_size = self.superblock.block_size * self.superblock.blocks_count

        # extract a volume name if present
        try:
            self.volume_name = self.superblock.volume_name.decode()
        except:
            self.volume_name = ""

        # extract a last mounted path if present
        try:
            self.last_mounted = self.superblock.last_mounted.decode()
        except:
            self.last_mounted = ""

        self.fs_uuid = uuid.UUID(bytes=self.superblock.uuid)

        if self.superblock.rev_level != 0:
            # Now check for each block group if there is a copy of the
            # superblock except if the sparse super block features is set
            # (section 2.5).
            # Find the right offset and then check if the magic byte is at
            # that location, unless the block size is 1024, then it will be at
            # the location + 1024.
            for i in range(1, block_groups):
                # super blocks are always present in block group 0 and 1, except
                # if the block size = 1024
                # Block group 0 contains the original superblock, which has
                # already been processed.
                if not self.superblock.ro_compat_sparse_super:
                    if self.superblock.block_size == 1024:
                        blockoffset = i*self.superblock.block_size*self.superblock.blocks_per_group+1024
                    else:
                        blockoffset = i*self.superblock.block_size*self.superblock.blocks_per_group
                else:
                    # if the sparse superblock feature is enabled
                    # the superblock can be found in each superblock
                    # that is a power of 3, 5 or 7
                    sparsefound = False
                    for p in [3, 5, 7]:
                        if pow(p, int(math.log(i, p))) == i:
                            if self.superblock.block_size == 1024:
                                blockoffset = i*self.superblock.block_size*self.superblock.blocks_per_group+1024
                            else:
                                blockoffset = i*self.superblock.block_size*self.superblock.blocks_per_group
                            sparsefound = True
                            break
                    if not sparsefound:
                        # for anything that is not a power of 3, 5 or 7
                        continue

                # jump to the location of the backup of the superblock
                # and parse it using kaitai struct
                self.infile.seek(blockoffset)
                try:
                    superblock = ext2.Ext2.SuperBlockStruct.from_io(self.infile)
                except (Exception, ValidationFailedError) as e:
                    raise UnpackParserException(e.args)

        # now some extra sanity checks: run tune2fs and other tools to see
        # if the file system can be read. These tools can work with trailing
        # data, but if there is any data preceding the file system then the
        # data has to be carved first.
        havetmpfile = False
        if self.offset != 0:
            # if files are larger than a certain limit, then os.sendfile()
            # won't write more data than 2147479552 so write bytes
            # out in chunks. Reference:
            # https://bugzilla.redhat.com/show_bug.cgi?id=612839
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            if self.unpacked_size > 2147479552:
                bytesleft = self.unpacked_size
                bytestowrite = min(bytesleft, 2147479552)
                readoffset = self.offset
                while bytesleft > 0:
                    os.sendfile(temporary_file[0], self.infile.fileno(), readoffset, bytestowrite)
                    bytesleft -= bytestowrite
                    readoffset += bytestowrite
                    bytestowrite = min(bytesleft, 2147479552)
            else:
                os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()
            havetmpfile = True

        if havetmpfile:
            p = subprocess.Popen(['tune2fs', '-l', temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(['tune2fs', '-l', self.fileresult.filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        failure = False

        if p.returncode != 0:
            failure = True

        if not failure:
            # Now read the contents of the file system with e2ls, starting
            # with the root directory.
            ext2dirstoscan = collections.deque([''])

            while True:
                try:
                    ext2dir = ext2dirstoscan.popleft()
                except IndexError:
                    # there are no more entries to process
                    break
                if havetmpfile:
                    p = subprocess.Popen(['e2ls', '-lai', temporary_file[1] + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    p = subprocess.Popen(['e2ls', '-lai', str(self.fileresult.filename) + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (outputmsg, errormsg) = p.communicate()
                if p.returncode != 0:
                    failure = True
                    break

                dirlisting = outputmsg.rstrip().split(b'\n')

                # socket, symbolic link, regular, block device, directory
                # charactter device, FIFO/pipe
                octals = [('s', 0o140000), ('l', 0o120000), ('-', 0o100000),
                          ('b', 0o60000), ('d', 0o40000), ('c', 0o10000),
                          ('p', 0o20000)]

        if havetmpfile:
            os.unlink(temporary_file[1])

        check_condition(not failure, "sanity check with tune2fs or e2ls failed")


    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['ext2', 'filesystem']
        metadata = {}
        metadata['uuid'] = self.fs_uuid

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
