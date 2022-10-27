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
import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import cramfs


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

        try:
            self.data = cramfs.Cramfs.from_io(self.infile)
        except ValidationFailedError as e:
            raise UnpackParserException(e.args)

        # currently only version 2 is supported
        check_condition(self.data.header.version == 2, "unsupported cramfs version")

        # keep a mapping of inode numbers to metadata
        # and a reverse mapping from offset to inode
        inodes = {}
        offset_to_inode = {}

        # See defines in Linux kernel include/uapi/linux/cramfs_fs.h
        # for the width/length of modes, lengths, etc.
        inode_counter = 0
        for inode in self.data.data.inodes:
            # only use valid modes
            if type(inode.file_mode) == int:
                raise UnpackParserException("unsupported file mode")

            # the data cannot be outside of the file
            check_condition(inode.ofs_data <= self.infile.size,
                            "data cannot be outside of file")

            if inode_counter != 0:
                check_condition(inode.len_name != 0, "cannot have zero length filename")

            # sanity checks for block pointers
            if inode.file_mode == cramfs.Cramfs.Modes.regular or inode.file_mode == cramfs.Cramfs.Modes.link:
                start_offset = inode.ofs_data + inode.nblocks * 4
                for block_pointer in inode.block_pointers.block_pointers:
                    check_condition(block_pointer <= self.infile.size,
                                    "data cannot be outside of file")

                    # sanity check for zlib compressed data
                    self.infile.seek(start_offset)
                    buf = self.infile.read(block_pointer - start_offset)
                    try:
                        zlib.decompress(buf)
                    except zlib.error as e:
                        raise UnpackParserException(e.args)
                    start_offset = block_pointer

            inodes[inode_counter] = {'name': inode.name, 'mode': inode.file_mode.name,
                             'data_offset': inode.ofs_data, 'uid': inode.uid,
                             'gid': inode.gid, 'size': inode.len_decompressed}

            inode_counter += 1

        '''
        # for now unpack using fsck.cramfs from util-linux. In the future
        # this should be replaced by an own unpacker.
        inode_offset_to_directory = {}

        # now verify the data
        for inode in inodes:
            if inodes[inode]['mode'] == 'directory':
                # the data offset points to the offset of
                # the first inode in the directory
                if inodes[inode]['data_offset'] != 0:
                    # verify if there is a valid inode
                    check_condition(inodes[inode]['data_offset'] in offset_to_inode,
                                    "invalid directory entry")
        '''

        # unpack in a temporary directory to rule out things like CRC errors.
        # fsck.cramfs expects to create the directory itself so only create
        # the name and then let fsck.cramfs create the directory.

        # first get a temporary name
        self.cramfs_unpack_directory = tempfile.mkdtemp(dir=self.scan_environment.temporarydirectory)

        # remove the directory. Possible race condition?
        shutil.rmtree(self.cramfs_unpack_directory)

        if self.offset == 0 and self.data.header.len_cramfs == self.infile.filesize:
            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % self.cramfs_unpack_directory, self.infile.name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()
        else:
            temporaryfile = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporaryfile[0], self.infile.fileno(), self.offset, self.data.header.len_cramfs)
            os.fdopen(temporaryfile[0]).close()

            p = subprocess.Popen(['fsck.cramfs', '--extract=%s' % self.cramfs_unpack_directory, temporaryfile[1]],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (outputmsg, errormsg) = p.communicate()
            os.unlink(temporaryfile[1])

        if p.returncode != 0:
            # clean up the temporary directory. It could be that
            # fsck.cramfs actually didn't create the directory due to
            # other errors, such as a CRC error.
            if os.path.exists(self.cramfs_unpack_directory):
                shutil.rmtree(self.cramfs_unpack_directory)

            raise UnpackParserException("cannot unpack cramfs")

    def unpack(self, meta_directory):
        # move the unpacked files
        # move contents of the unpacked file system
        for result in pathlib.Path(self.cramfs_unpack_directory).glob('**/*'):
            relative_result = result.relative_to(self.cramfs_unpack_directory)

            file_path = pathlib.Path(relative_result)

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
        shutil.rmtree(self.cramfs_unpack_directory)
        return unpacked_files

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.header.len_cramfs

    labels = ['cramfs', 'filesystem']
    metadata = {}
