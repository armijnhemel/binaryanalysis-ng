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
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import ext2

ENCODINGS_TO_TRANSLATE = ['utf-8', 'ascii', 'latin-1', 'euc_jp', 'euc_jis_2004',
                          'jisx0213', 'iso2022_jp', 'iso2022_jp_1',
                          'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3',
                          'iso2022_jp_ext', 'iso2022_kr', 'shift_jis',
                          'shift_jis_2004', 'shift_jisx0213']

# socket, symbolic link, regular, block device, directory
# charactter device, FIFO/pipe
OCTALS = [('s', 0o140000), ('l', 0o120000), ('-', 0o100000),
          ('b', 0o60000), ('d', 0o40000), ('c', 0o10000),
          ('p', 0o20000)]


class Ext2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0x438,  b'\x53\xef')
    ]
    pretty_name = 'ext2'

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
        self.havetmpfile = False
        if self.offset != 0:
            # if files are larger than a certain limit, then os.sendfile()
            # won't write more data than 2147479552 so write bytes
            # out in chunks. Reference:
            # https://bugzilla.redhat.com/show_bug.cgi?id=612839
            self.temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            if self.unpacked_size > 2147479552:
                bytesleft = self.unpacked_size
                bytestowrite = min(bytesleft, 2147479552)
                readoffset = self.offset
                while bytesleft > 0:
                    os.sendfile(self.temporary_file[0], self.infile.fileno(), readoffset, bytestowrite)
                    bytesleft -= bytestowrite
                    readoffset += bytestowrite
                    bytestowrite = min(bytesleft, 2147479552)
            else:
                os.sendfile(self.temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(self.temporary_file[0]).close()
            self.havetmpfile = True

        if self.havetmpfile:
            p = subprocess.Popen(['tune2fs', '-l', self.temporary_file[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

            # store a mapping for inodes and files. This is needed to detect
            # hard links, where files have the same inode.
            self.inode_to_file = {}

            # store name of file, plus stat information
            self.files = []

            while True:
                try:
                    ext2dir = ext2dirstoscan.popleft()
                except IndexError:
                    # there are no more entries to process
                    break
                if self.havetmpfile:
                    p = subprocess.Popen(['e2ls', '-lai', self.temporary_file[1] + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    p = subprocess.Popen(['e2ls', '-lai', str(self.fileresult.filename) + ":" + ext2dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (outputmsg, errormsg) = p.communicate()
                if p.returncode != 0:
                    failure = True
                    break

                dirlisting = outputmsg.rstrip().split(b'\n')

                for d in dirlisting:
                    # ignore deleted files
                    if d.strip().startswith(b'>'):
                        continue
                    dirsplit = re.split(b'\s+', d.strip(), 7)
                    if len(dirsplit) != 8:
                        failure = True
                        break

                    (inode, filemode, userid, groupid, size, filedate, filetime, ext2name) = re.split(b'\s+', d.strip(), 7)

                    try:
                        filemode = int(filemode, base=8)
                    except ValueError:
                        # newer versions of e2tools (starting 0.1.0) pretty print
                        # the file mode instead of printing a number so recreate it
                        if len(filemode) != 10:
                            failure = True
                            break

                        # instantiate the file mode and look at the first character
                        # as that is the only one used during checks.
                        filemode = filemode.decode()
                        new_filemode = 0
                        for fm in OCTALS:
                            if filemode[0] == fm[0]:
                                new_filemode = fm[1]
                                break

                        filemode = new_filemode

                    # try to make sense of the filename by decoding it first.
                    # This might fail.
                    namedecoded = False
                    for c in ENCODINGS_TO_TRANSLATE:
                        try:
                            ext2name = ext2name.decode(c)
                            namedecoded = True
                            break
                        except Exception as e:
                            pass
                    if not namedecoded:
                        failure = True
                        break

                    # Check the different file types
                    if stat.S_ISDIR(filemode):
                        # It is a directory, so create it and then add
                        # it to the scanning queue, unless it is . or ..
                        if ext2name == '.' or ext2name == '..':
                            continue
                        newext2dir = os.path.join(ext2dir, ext2name)
                        ext2dirstoscan.append(newext2dir)

                    fullext2name = os.path.join(ext2dir, ext2name)

                    self.files.append((fullext2name, inode, filemode))
                    if stat.S_ISREG(filemode):
                        if inode not in self.inode_to_file:
                            self.inode_to_file[inode] = fullext2name
                            # use e2cp to copy the file
                            if self.havetmpfile:
                                p = subprocess.Popen(['e2cp', self.temporary_file[1] + ":" + fullext2name, os.devnull], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            else:
                                p = subprocess.Popen(['e2cp', str(self.fileresult.filename) + ":" + fullext2name, os.devnull], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            (outputmsg, errormsg) = p.communicate()
                            if p.returncode != 0:
                                failure = True
                                break

        if failure and self.havetmpfile:
            os.unlink(self.temporary_file[1])

        check_condition(not failure, "sanity check with tune2fs, e2cp or e2ls failed")

    def unpack(self):
        unpacked_files = []

        # Now read the contents of the file system with e2ls, starting
        # with the root directory.
        ext2dirstoscan = collections.deque([''])

        # store a mapping for inodes and files. This is needed to detect
        # hard links, where files have the same inode.
        for f in self.files:
            ext2name, inode, filemode = f
            # Check the different file types
            outfile_rel = self.rel_unpack_dir / ext2name
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            if stat.S_ISDIR(filemode):
                os.makedirs(outfile_full, exist_ok=True)
                fr = FileResult(self.fileresult, outfile_rel, set(['directory']))
                unpacked_files.append(fr)
            elif stat.S_ISBLK(filemode):
                # ignore block devices
                continue
            elif stat.S_ISCHR(filemode):
                # ignore character devices
                continue
            elif stat.S_ISFIFO(filemode):
                # ignore FIFO
                continue
            elif stat.S_ISSOCK(filemode):
                # ignore sockets
                continue
            elif stat.S_ISLNK(filemode):
                # e2cp cannot copy symbolic links
                # so just record that there is a symbolic link
                # TODO: process symbolic links
                pass
            elif stat.S_ISREG(filemode):
                if self.inode_to_file[inode] == ext2name:
                    # use e2cp to copy the file
                    if self.havetmpfile:
                        p = subprocess.Popen(['e2cp', self.temporary_file[1] + ":" + ext2name, outfile_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        p = subprocess.Popen(['e2cp', str(self.fileresult.filename) + ":" + ext2name, outfile_full], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (outputmsg, errormsg) = p.communicate()
                    fr = FileResult(self.fileresult, outfile_rel, set())
                else:
                    # hardlink
                    target_rel = self.rel_unpack_dir / self.inode_to_file[inode]
                    target_full = self.scan_environment.unpack_path(target_rel)
                    target_full.link_to(outfile_full)
                    fr = FileResult(self.fileresult, outfile_rel, set(['hardlink']))
                unpacked_files.append(fr)

        if self.havetmpfile:
            os.unlink(self.temporary_file[1])

        return unpacked_files

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
