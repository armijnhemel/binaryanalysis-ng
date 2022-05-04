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
import shutil
import stat
import subprocess
import tempfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class CramfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x45\x3d\xcd\x28'),
        (0, b'\x28\xcd\x3d\x45')
    ]
    pretty_name = 'cramfs'

    # a wrapper around shutil.copy2 to copy symbolic links instead of
    # following them and copying the data.
    def local_copy2(self, src, dest):
        '''Wrapper around shutil.copy2 for squashfs unpacking'''
        return shutil.copy2(src, dest, follow_symlinks=False)

    def parse(self):
        check_condition(shutil.which('fsck.cramfs') is not None,
                        'fsck.cramfs program not found')

        # read the magic to see what the endianness is
        buf = self.infile.read(4)
        if buf == b'\x45\x3d\xcd\x28':
            byteorder = 'little'
            bigendian = False
        else:
            byteorder = 'big'
            bigendian = True

        # length in bytes
        buf = self.infile.read(4)
        self.cramfs_size = int.from_bytes(buf, byteorder=byteorder)
        check_condition(self.offset + self.cramfs_size <= self.fileresult.filesize,
                        "declared size larger than file")

        # feature flags
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for feature flags")
        featureflags = int.from_bytes(buf, byteorder=byteorder)

        if featureflags & 1 == 1:
            cramfs_version = 2
        else:
            cramfs_version = 0

        # currently only version 2 is supported
        check_condition(cramfs_version == 2, "unsupported cramfs version")

        # reserved for future use, skip
        self.infile.seek(4, os.SEEK_CUR)

        # signature
        buf = self.infile.read(16)
        check_condition(buf == b'Compressed ROMFS', "invalid signature")

        # cramfs_info struct (32 bytes)
        # crc32
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for crc32 field")
        cramfs_crc32 = int.from_bytes(buf, byteorder=byteorder)

        # edition
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for cramfs edition field")
        cramfs_edition = int.from_bytes(buf, byteorder=byteorder)

        # blocks
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for blocks field")
        cramfs_blocks = int.from_bytes(buf, byteorder=byteorder)

        # files
        buf = self.infile.read(4)
        check_condition(len(buf) == 4, "not enough data for files field")
        cramfs_files = int.from_bytes(buf, byteorder=byteorder)

        # user defined name
        buf = self.infile.read(16)
        check_condition(len(buf) == 16, "not enough data for user defined name field")
        try:
            volumename = buf.split(b'\x00', 1)[0].decode()
        except UnicodeDecodeError:
            raise UnpackParserException('invalid volume name')

        # then process the inodes.

        # keep a mapping of inode numbers to metadata
        # and a reverse mapping from offset to inode
        inodes = {}
        offsettoinode = {}

        # See defines in Linux kernel include/uapi/linux/cramfs_fs.h
        # for the width/length of modes, lengths, etc.
        for inode in range(0, cramfs_files):
            # store the current offset, as it is used by directories
            curoffset = self.infile.tell()

            # 2 bytes mode width, 2 bytes uid width
            buf = self.infile.read(2)
            check_condition(len(buf) == 2, "not enough data for inode")
            inode_mode = int.from_bytes(buf, byteorder=byteorder)

            # determine the kind of file
            if stat.S_ISDIR(inode_mode):
                mode = 'directory'
            elif stat.S_ISCHR(inode_mode):
                mode = 'chardev'
            elif stat.S_ISBLK(inode_mode):
                mode = 'blockdev'
            elif stat.S_ISREG(inode_mode):
                mode = 'file'
            elif stat.S_ISFIFO(inode_mode):
                mode = 'fifo'
            elif stat.S_ISLNK(inode_mode):
                mode = 'symlink'
            elif stat.S_ISSOCK(inode_mode):
                mode = 'socket'

            buf = self.infile.read(2)
            check_condition(len(buf) == 2, "not enough data for inode")
            inode_uid = int.from_bytes(buf, byteorder=byteorder)

            # 3 bytes size width, 1 bytes gid width
            buf = self.infile.read(3)
            check_condition(len(buf) == 3, "not enough data for inode")

            # size of the decompressed inode
            inode_size = int.from_bytes(buf, byteorder=byteorder)

            buf = self.infile.read(1)
            check_condition(len(buf) == 1, "not enough data for inode")
            inode_gid = int.from_bytes(buf, byteorder=byteorder)

            # length of the name and offset. The first 6 bits are for
            # the name length (divided by 4), the last 26 bits for the
            # offset of the data (divided by 4). This is regardless of
            # the endianness!
            # The name is padded to 4 bytes. Because the original name length
            # is restored by multiplying with 4 there is no need for a
            # check for padding.
            buf = self.infile.read(4)
            check_condition(len(buf) == 4, "not enough data for inode")
            namelenbytes = int.from_bytes(buf, byteorder=byteorder)

            if bigendian:
                # get the most significant bits and then shift 26 bits
                name_length = ((namelenbytes & 4227858432) >> 26) * 4

                # 0b11111111111111111111111111 = 67108863
                data_offset = (namelenbytes & 67108863) * 4
            else:
                # 0b111111 = 63
                name_length = (namelenbytes & 63) * 4

                # get the bits, then shift 6 bits
                data_offset = ((namelenbytes & 67108863) >> 6) * 4

            # the data cannot be outside of the file
            check_condition(self.offset + data_offset <= self.fileresult.filesize,
                            "data cannot be outside of file")

            # if this is the root node there won't be any data
            # following, so continue with the next inode.
            if inode == 0:
                continue

            check_condition(name_length != 0, "cannot have zero length filename")

            buf = self.infile.read(name_length)
            try:
                inode_name = buf.split(b'\x00', 1)[0].decode()
            except UnicodeDecodeError:
                raise UnpackParserException('invalid filename')

            inodes[inode] = {'name': inode_name, 'mode': mode, 'offset': curoffset,
                             'data_offset': data_offset, 'uid': inode_uid,
                             'gid': inode_gid, 'size': inode_size}

            offsettoinode[curoffset] = inode

        inodeoffsettodirectory = {}

        # for now unpack using fsck.cramfs from util-linux. In the future
        # this should be replaced by an own unpacker.

        # now verify the data
        for inode in inodes:
            # don't recreate device files
            if inodes[inode]['mode'] == 'blockdev':
                continue
            if inodes[inode]['mode'] == 'chardev':
                continue
            if inodes[inode]['mode'] == 'file':
                pass
            elif inodes[inode]['mode'] == 'directory':
                # the data offset points to the offset of
                # the first inode in the directory
                if inodes[inode]['data_offset'] != 0:
                    # verify if there is a valid inode
                    check_condition(inodes[inode]['data_offset'] in offsettoinode,
                                    "invalid directory entry")

        self.havetmpfile = False

        # unpack in a temporary directory to rule out things like CRC errors.
        # fsck.cramfs expects to create the directory itself so only create
        # the name and then let fsck.cramfs create the directory.

        # first get a temporary name
        cramfs_unpack_directory = tempfile.mkdtemp(dir=self.scan_environment.temporarydirectory)

        # remove the directory. Possible race condition?
        shutil.rmtree(cramfs_unpack_directory)

        if self.offset == 0 and self.cramfs_size == self.fileresult.filesize:
            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfs_unpack_directory, self.fileresult.filename],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            temporaryfile = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporaryfile[0], self.infile.fileno(), self.offset, self.cramfs_size)
            os.fdopen(temporaryfile[0]).close()
            self.havetmpfile = True

            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfs_unpack_directory, temporaryfile[1]],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (outputmsg, errormsg) = p.communicate()

        # clean up
        if self.havetmpfile:
            os.unlink(temporaryfile[1])

        if os.path.exists(cramfs_unpack_directory):
            shutil.rmtree(cramfs_unpack_directory)

        if p.returncode != 0:
            # clean up the temporary directory. It could be that
            # fsck.cramfs actually didn't create the directory due to
            # other errors, such as a CRC error.
            raise UnpackParserException("cannot unpack cramfs")

    def unpack(self):
        unpacked_files = []

        # create a temporary directory and remove it again
        # fsck.cramfs cannot unpack to an existing directory
        # and move contents after unpacking.
        cramfs_unpack_directory = tempfile.mkdtemp(dir=self.scan_environment.temporarydirectory)
        shutil.rmtree(cramfs_unpack_directory)

        if not self.havetmpfile:
            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfs_unpack_directory, self.fileresult.filename],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            temporaryfile = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporaryfile[0], self.infile.fileno(), self.offset, self.cramfs_size)
            os.fdopen(temporaryfile[0]).close()

            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % cramfs_unpack_directory, temporaryfile[1]],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outputmsg, errormsg) = p.communicate()

        if self.havetmpfile:
            os.unlink(temporaryfile[1])

        # move the unpacked files
        # move contents of the unpacked file system
        for result in pathlib.Path(cramfs_unpack_directory).glob('**/*'):
            relative_result = result.relative_to(cramfs_unpack_directory)
            outfile_rel = self.rel_unpack_dir / relative_result
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)

            if result.is_symlink():
                self.local_copy2(result, outfile_full)
            elif result.is_dir():
                os.makedirs(outfile_full, exist_ok=True)
                outfile_full.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            elif result.is_file():
                self.local_copy2(result, outfile_full)
                outfile_full.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            else:
                continue

            # then add the file to the result set
            fr = FileResult(self.fileresult, outfile_rel, set())
            unpacked_files.append(fr)

        # clean up the temporary directory
        shutil.rmtree(cramfs_unpack_directory)
        return unpacked_files

    # no need to carve from the file
    def carve(self):
        pass

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.cramfs_size

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['cramfs', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
