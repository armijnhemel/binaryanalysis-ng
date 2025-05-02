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

import collections
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import erofs


class ErofsUnpacker(UnpackParser):
    extensions = []
    signatures = [
        (1024, b'\xe2\xe1\xf5\xe0')
    ]
    pretty_name = 'erofs'

    def parse(self):
        if shutil.which('fsck.erofs') is None:
            raise UnpackParserException("fsck.erofs not installed")

        try:
            self.data = erofs.Erofs.from_io(self.infile)

            # run fsck's own tools before parsing a bit with Kaitai Struct
            p = subprocess.Popen(['fsck.erofs', '--extract', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            if p.returncode != 0:
                raise UnpackParserException("invalid erofs image according to fsck.erofs")

            # first assume that the inodes are not compressed or
            # chunks, just inline or plain. If not, record as such.
            self.inline = True

            # force read the data to force Kaitai Struct to evaluate
            nr_of_blocks = len(self.data.blocks)

            # walk the inodes
            inodes = collections.deque()
            inodes.append(('', '', erofs.Erofs.FileTypes.directory, self.data.root_inode))
            while True:
                try:
                    name, parent, file_type, inode = inodes.popleft()

                    # sanity check for inode_layout. Ideally this should have
                    # been done in the Kaitai Struct definition, but 'valid'
                    # checks are not allowed in instances (yet).
                    check_condition(inode.inode_layout in erofs.Erofs.Inode.Layouts,
                                    "invalid inode layout")

                    # only process "inline" inodes for now
                    if inode.inode_layout not in [erofs.Erofs.Inode.Layouts.inline, erofs.Erofs.Inode.Layouts.plain]:
                        self.inline = False

                    if inode.inode.is_dir:
                        check_condition(file_type == erofs.Erofs.FileTypes.directory,
                                            "directory not declared as directory")
                        # recurse into the directory tree
                        for d in inode.data.dir_entries.entries:
                            if d.name.name in ['.', '..']:
                                # sanity check: make sure these are tagged as 'directory'
                                check_condition(d.file_type == erofs.Erofs.FileTypes.directory,
                                                "directory not declared as directory")
                                continue
                            inodes.append((d.name.name, name, d.file_type, d.inode))
                    elif inode.inode.is_regular and self.inline:
                        check_condition(file_type == erofs.Erofs.FileTypes.regular_file,
                                            "directory not declared as directory")
                        # force read the data to force Kaitai Struct to evaluate
                        d = inode.data.node_data
                    elif inode.inode.is_link:
                        check_condition(file_type == erofs.Erofs.FileTypes.symlink,
                                            "directory not declared as directory")
                except IndexError:
                    break
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.superblock.header.len_file

    def unpack(self, meta_directory):
        if self.inline:
            inodes = collections.deque()
            inodes.append(('', '', erofs.Erofs.FileTypes.directory, self.data.root_inode))

            # keep track of inodes to facilitate hard links
            inodes_to_name = {}
            while True:
                try:
                    is_hardlink = False
                    name, parent, file_type, inode = inodes.popleft()
                    file_path = pathlib.Path(parent, name)

                    if inode.inode.body.ino in inodes_to_name:
                        is_hardlink = True
                    else:
                        inodes_to_name[inode.inode.body.ino] = file_path

                    if inode.inode.is_dir:
                        if file_path.name != '':
                            meta_directory.unpack_directory(file_path)

                        # recurse into the directory tree
                        for d in inode.data.dir_entries.entries:
                            if d.name.name in ['.', '..']:
                                continue
                            inodes.append((d.name.name, name, d.file_type, d.inode))
                    elif inode.inode.is_regular:
                        if is_hardlink:
                            target = inodes_to_name[inode.inode.body.ino]
                            meta_directory.unpack_hardlink(file_path, target)
                        else:
                            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                                outfile.write(inode.data.node_data)
                                outfile.write(inode.data.last_inline_data)
                                yield unpacked_md
                    elif inode.inode.is_link:
                        target = pathlib.Path(inode.data.link_data)
                        meta_directory.unpack_symlink(file_path, target)

                except IndexError:
                    break
        else:
            # create a temporary directory, unpack contents
            # and copy the contents to the actual meta directory
            unpack_directory = pathlib.Path(tempfile.mkdtemp(dir=self.configuration.temporary_directory))

            p = subprocess.Popen(['fsck.erofs', f'--extract={unpack_directory}', self.infile.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            (outputmsg, errormsg) = p.communicate()

            # force the permissions of the unpacking directory as
            # sometimes a directory is created without write permission
            # (so difficult to remove)
            unpack_directory.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # move the unpacked files
            # move contents of the unpacked file system
            for result in pathlib.Path(unpack_directory).glob('**/*'):
                file_path = result.relative_to(unpack_directory)

                if result.is_symlink():
                    meta_directory.unpack_symlink(file_path, result.readlink())
                elif result.is_dir():
                    result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                    meta_directory.unpack_directory(file_path)
                elif result.is_file():
                    result.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                    with meta_directory.unpack_regular_file_no_open(file_path) as (unpacked_md, outfile):
                        self.local_copy2(result, outfile)
                        yield unpacked_md
                else:
                    continue

            # clean up the temporary directory
            shutil.rmtree(unpack_directory)

            (outputmsg, errormsg) = p.communicate()

    # a wrapper around shutil.copy2 to copy symbolic links instead of
    # following them and copying the data.
    def local_copy2(self, src, dest):
        '''Wrapper around shutil.copy2 for erofs unpacking'''
        return shutil.copy2(src, dest, follow_symlinks=False)

    labels = ['erofs', 'filesystem']

    @property
    def metadata(self):
        metadata = {'uuid': self.data.superblock.header.uuid}
        metadata['name'] = self.data.superblock.header.volume_name
        return metadata
