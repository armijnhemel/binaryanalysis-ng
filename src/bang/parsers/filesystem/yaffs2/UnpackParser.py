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

# YAFFS2 is a file system that was at some point popular on Android devices
# but which seems to have lost its popularity. It can still be found
# every now and then. The following method unpacks them, but only images
# created by mkyaffs2image, not any flash dumps from a live device with
# deleted chunks (TODO).
#
# YAFFS2 does not have any magic numbers, so it is not always easy to
# recognize. There are a few common patterns that can be searched for.
# These patterns can be found by creating images with mkyaffs2image and
# analyzing them.
#
# Some notes:
#
# https://wiki.sleuthkit.org/index.php?title=YAFFS2
# https://wiki.sleuthkit.org/index.php?title=YAFFS2_Implementation_Notes
#
# Presentation (relevant page: 10):
#
# http://tree.celinuxforum.org/CelfPubWiki/ELCEurope2007Presentations?action=AttachFile&do=get&target=yaffs.pdf
#
# The layout of the spare data can be found in the YAFFS2 header
# files (LGPL 2.1 licensed):
#
# https://android.googlesource.com/platform/external/yaffs2/+/donut-release/yaffs2/yaffs_packedtags2.h
#
# Layout of the chunk:
#
# https://android.googlesource.com/platform/external/yaffs2/+/donut-release/yaffs2/yaffs_guts.h#290
#
# A YAFFS2 file system is basically a concatenation of chunks, with associated
# metadata which is either stored separately from the data ("out of band")
# or with the data ("in band").
#
# YAFFS2 images can be created using mkyaff2simage, which can be found at
# git://www.aleph1.co.uk/yaffs2
#
# Images with in band tags can be made with yaffs2utils from
# https://github.com/OpenNuvoton/NUC970_Linux_Applications/tree/master/yaffs2utils
#
# Note: it seems that regular images made with the latter yaffs2utils cannot be
# unpacked.

import os
import pathlib

from bang.UnpackParser import UnpackParser, check_condition

# the different yaffs2 chunk types
YAFFS_OBJECT_TYPE_UNKNOWN = 0
YAFFS_OBJECT_TYPE_FILE = 1
YAFFS_OBJECT_TYPE_SYMLINK = 2
YAFFS_OBJECT_TYPE_DIRECTORY = 3
YAFFS_OBJECT_TYPE_HARDLINK = 4
YAFFS_OBJECT_TYPE_SPECIAL = 5

# the maximum name length and alias length. These are hardcoded in
# the YAFFS2 code and only this value has been observed, but it
# could be that other values exist.
YAFFS_MAX_NAME_LENGTH = 255
YAFFS_MAX_ALIAS_LENGTH = 159

# flags for inband tags (from yaffs_packedtags2.c )
EXTRA_HEADER_INFO_FLAG = 0x80000000
EXTRA_SHRINK_FLAG = 0x40000000
EXTRA_SHADOWS_FLAG = 0x20000000
EXTRA_SPARE_FLAGS = 0x10000000
ALL_EXTRA_FLAG = 0xf0000000

EXTRA_OBJECT_TYPE_SHIFT = 28
EXTRA_OBJECT_TYPE_MASK = 0x0f << EXTRA_OBJECT_TYPE_SHIFT

# common values for chunk/spare combinations, most common
# combinations first.
# The default in mkyaffs2image is (2048, 64) and Android
# primarily uses (1024, 32).
#
# Most devices use "out of band" (OOB) tags, but
# some devices use "in band" tags to save flash space.
# in band tags always seem to be 16 bytes long
# (4080, 16) is an example of a common size for inline tags
# Most common combinations (spare size = chunk size/32) are listed first
CHUNKS_AND_SPARES = [(512, 16), (1024, 32), (2048, 64), (4196, 128),
                     (8192, 256), (16384, 512), (512, 32), (512, 64),
                     (512, 128), (1024, 16), (1024, 64), (1024, 128),
                     (2048, 16), (2048, 32), (2048, 128), (4096, 16),
                     (4096, 32), (4096, 64), (8192, 16), (8192, 32),
                     (8192, 64), (8192, 128), (8192, 448), (8192, 512),
                     (16384, 16), (16384, 32), (16384, 64), (16384, 128),
                     (16384, 256), (16384, 448), (4080, 16), (8176, 16),
                     (2032, 16), (496, 16), (16368, 16)]


class Yaffs2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        (0, b'\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        # big endian, do not use right now
        #(0, b'\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff'),
        #(0, b'\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff')
    ]
    pretty_name = 'yaffs2'

    def parse(self):
        self.byteorder = 'little'
        self.yaffs2_metadata = {}
        data_unpacked = False

        # then try to read the file system for various chunk/spare
        # combinations until either data has been successfully parsed
        # or it is clear that it is not a yaffs2 image at all.
        for (chunk_size, spare_size) in CHUNKS_AND_SPARES:

            # seek to the start
            cur_offset = 0
            self.infile.seek(cur_offset)

            # keep a mapping of object ids to latest chunk id
            object_id_to_latest_chunk = {}

            # keep a mapping of object ids to type
            self.object_id_to_type = {}

            # keep a mapping of object ids to name
            self.object_id_to_name = {}

            # store if element with object id 1 has been seen. Most, but not all,
            # YAFFS2 images have this as a separate chunk.
            seen_root_element = False
            is_first_element = True

            # store if this is an inband image
            self.inband = False

            # keep some metadata about files, simulate
            # unpacking, but don't write data
            last_open_size = 0
            last_open = None
            previous_object_id = 0

            self.last_valid_offset = cur_offset

            # read the chunks and spares until:
            # - end of file
            # - end of file system (in case of carving)
            # - verification checks fail
            #
            # The metadata is in the 'spare' part.
            while True:
                if self.last_valid_offset + chunk_size + spare_size > self.infile.size:
                    break

                self.last_valid_offset = self.infile.tell()

                # skip the chunk and read relevant spare data.
                self.infile.seek(chunk_size, os.SEEK_CUR)

                # read the sequence number
                spare_bytes = self.infile.read(4)
                sequence_number = int.from_bytes(spare_bytes, byteorder=self.byteorder)

                # mkyaffs2image uses 0xff for padding. Skip these bytes
                # and continue reading to determine the real size of the
                # yaffs2 image.
                if sequence_number == 0xffffffff:
                    self.infile.seek(self.last_valid_offset + chunk_size + spare_size)
                    continue

                # read the object id
                spare_bytes = self.infile.read(4)
                object_id = int.from_bytes(spare_bytes, byteorder=self.byteorder)

                # object id 0 is invalid so likely this is a false positive.
                if object_id == 0:
                    break

                # read the chunk id
                spare_bytes = self.infile.read(4)
                chunk_id = int.from_bytes(spare_bytes, byteorder=self.byteorder)

                # first check if the relevant info is stored in an inband tag
                # or in a normal tag. Inbound tags are described in the YAFFS2
                # code in the file yaffs_packedtags2.c
                #
                # For inbound tags some data (object id, chunk id) are
                # mixed with the actual data, so extract them first.
                if chunk_id & EXTRA_HEADER_INFO_FLAG == EXTRA_HEADER_INFO_FLAG:
                    if not is_first_element and not self.inband:
                        # can't mix inband and out of band tags
                        break

                    # store the original chunk_id as it will be needed later
                    orig_chunk_id = chunk_id

                    # extract the object_id
                    object_id = object_id & ~EXTRA_OBJECT_TYPE_MASK

                    # the chunk_id will have been changed ONLY for
                    # the chunk with id 0 and not for any chunks
                    # with data (files), so it is safe to simply
                    # set the chunk_id to 0 here (new chunk).
                    chunk_id = 0
                    self.inband = True

                # read the chunk byte count
                spare_bytes = self.infile.read(4)
                byte_count = int.from_bytes(spare_bytes, byteorder=self.byteorder)

                # depending on the object_id, chunk_id and object type the
                # chunk is either a continuation, or a new object.

                # if it is a continuation of an existing object, then the
                # chunk id cannot be 0, as that is the header.
                if chunk_id != 0:
                    # because it is a continuation object_id
                    # should already have a chunk associated with it
                    if object_id not in object_id_to_latest_chunk:
                        break

                    # chunk ids have to be sequential
                    if chunk_id - object_id_to_latest_chunk[object_id] != 1:
                        break

                    # only files can be spread over multiple chunks
                    if self.object_id_to_type[object_id] != YAFFS_OBJECT_TYPE_FILE:
                        break

                    object_id_to_latest_chunk[object_id] = chunk_id
                    data_unpacked = True
                else:
                    if last_open is not None:
                        if object_id_to_latest_chunk[previous_object_id] == 0:
                            if last_open_size != 0:
                                last_open = None
                                break

                    last_open = None

                    # object id should not have been seen yet
                    if object_id in object_id_to_latest_chunk:
                        break

                    # store latest chunk id for this object
                    object_id_to_latest_chunk[object_id] = chunk_id

                    # jump to the offset of the chunk and analyze
                    self.infile.seek(self.last_valid_offset)

                    # object type
                    object_bytes = self.infile.read(4)
                    chunk_object_type = int.from_bytes(object_bytes, byteorder=self.byteorder)

                    # check the object type
                    if chunk_object_type == YAFFS_OBJECT_TYPE_UNKNOWN:
                        break

                    # read the parent object id
                    parent_id_bytes = self.infile.read(4)
                    parent_object_id = int.from_bytes(parent_id_bytes, byteorder=self.byteorder)

                    if self.inband:
                        parent_object_id = orig_chunk_id & ~ALL_EXTRA_FLAG

                    # skip the name checksum (2 bytes)
                    self.infile.seek(2, os.SEEK_CUR)

                    # object name
                    # For some reason 2 extra bytes need to be read that have
                    # been initialized to 0xff
                    checkbytes = self.infile.read(YAFFS_MAX_NAME_LENGTH + 1 + 2)
                    try:
                        object_name = os.path.normpath(checkbytes.split(b'\x00', 1)[0].decode())

                        # sanity check, needs more TODO
                        if os.path.isabs(object_name):
                            object_name = os.path.relpath(object_name, '/')
                    except:
                        break

                    # yst_mode
                    stat_bytes = self.infile.read(4)
                    mode = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    # stat information: uid, gid, atime, mtime, ctime
                    stat_bytes = self.infile.read(4)
                    uid = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    stat_bytes = self.infile.read(4)
                    gid = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    stat_bytes = self.infile.read(4)
                    atime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    stat_bytes = self.infile.read(4)
                    mtime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    stat_bytes = self.infile.read(4)
                    ctime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                    # the object size. This only makes sense for files. The real
                    # size depends on the "high" value as well.
                    size_bytes = self.infile.read(4)
                    object_size_low = int.from_bytes(size_bytes, byteorder=self.byteorder)

                    # equiv_id, only makes sense for hard links
                    equiv_bytes = self.infile.read(4)
                    equiv_id = int.from_bytes(equiv_bytes, byteorder=self.byteorder)

                    # alias, only makes sense for symlinks
                    alias = self.infile.read(YAFFS_MAX_ALIAS_LENGTH + 1)

                    # rdev, only for special files (block/char)
                    rdev_bytes = self.infile.read(4)
                    rdev = int.from_bytes(rdev_bytes, byteorder=self.byteorder)

                    # skip some Windows specific structures
                    self.infile.seek(24, os.SEEK_CUR)

                    # skip some inband related structures
                    self.infile.seek(8, os.SEEK_CUR)

                    # object size high
                    size_bytes = self.infile.read(4)
                    object_size_high = int.from_bytes(size_bytes, byteorder=self.byteorder)

                    # element 1 is special, but not every yaffs2 file system
                    # seems to have element 1, so sometimes it needs to be
                    # artificially added.
                    if object_id != 1:
                        if is_first_element:
                            # artificially add object 1
                            self.object_id_to_type[1] = YAFFS_OBJECT_TYPE_DIRECTORY
                            self.object_id_to_name[1] = ''
                    else:
                        # sanity checks for the root element
                        if not is_first_element:
                            break
                        if chunk_object_type != YAFFS_OBJECT_TYPE_DIRECTORY:
                            break

                        # add the root element and skip to the next chunk
                        self.object_id_to_type[1] = YAFFS_OBJECT_TYPE_DIRECTORY
                        self.object_id_to_name[1] = ''
                        self.infile.seek(self.last_valid_offset + chunk_size + spare_size)
                        continue

                    if parent_object_id not in self.object_id_to_type:
                        break

                    # parent objects always have to be a directory
                    if self.object_id_to_type[parent_object_id] != YAFFS_OBJECT_TYPE_DIRECTORY:
                        break

                    # record a place holder object so hard links work
                    self.object_id_to_name[object_id] = ''

                    full_object_name = pathlib.Path(self.object_id_to_name[parent_object_id]) / object_name
                    self.object_id_to_name[object_id] = full_object_name

                    # sanity check for individual file types
                    if chunk_object_type == YAFFS_OBJECT_TYPE_FILE:
                        # extra sanity check: in case the chunk/spare
                        # combination is not known false positives can happen
                        # where a regular file with name '.' can seem to
                        # exist, when it actually doesn't.
                        if object_name == '.':
                            break

                        # first reconstruct the file size.
                        if object_size_high != 0xffffffff:
                            object_size = (object_size_high << 32) + object_size_low
                        else:
                            object_size = object_size_low
                        last_open_size = object_size
                        last_open = ''
                        previous_object_id = object_id
                    elif chunk_object_type == YAFFS_OBJECT_TYPE_SYMLINK:
                        try:
                            alias = alias.split(b'\x00', 1)[0].decode()
                        except:
                            break
                    elif chunk_object_type == YAFFS_OBJECT_TYPE_DIRECTORY:
                        pass
                    elif chunk_object_type == YAFFS_OBJECT_TYPE_HARDLINK:
                        if equiv_id not in self.object_id_to_name:
                            break
                    elif chunk_object_type == YAFFS_OBJECT_TYPE_SPECIAL:
                        pass
                    else:
                        break

                    self.object_id_to_type[object_id] = chunk_object_type
                    is_first_element = False
                    data_unpacked = True

                if self.infile.tell() == self.infile.size:
                    break

                # skip to the next chunk/spare
                self.infile.seek(self.last_valid_offset + chunk_size + spare_size)
                self.last_valid_offset = self.infile.tell()

            if last_open is not None:
                if object_id_to_latest_chunk[previous_object_id] == 0:
                    if last_open_size != 0:
                        # something is wrong here
                        break

            if data_unpacked:
                self.unpackedsize = self.last_valid_offset
                self.yaffs2_metadata['chunk size'] = chunk_size
                self.yaffs2_metadata['spare size'] = spare_size
                self.infile.seek(self.last_valid_offset)
                break

        check_condition(data_unpacked, "no valid/suppported yaffs2 image found")
        check_condition(self.yaffs2_metadata, "no valid/suppported yaffs2 image found")

    def unpack(self, meta_directory):
        unpacked_mds = {}

        chunk_size = self.yaffs2_metadata['chunk size']
        spare_size = self.yaffs2_metadata['spare size']

        # seek to the start of the data
        cur_offset = 0
        self.infile.seek(cur_offset)

        # keep a mapping of object ids to latest chunk id
        object_id_to_latest_chunk = {}

        # keep a mapping of object ids to file size
        # for sanity checks
        object_id_to_size = {}

        # store the meta directory for the last open file for an object
        last_open = None
        last_open_size = 0
        previous_object_id = 0

        # store if element with object id 1 has been seen. Most, but not all,
        # YAFFS2 images have this as a separate chunk.
        seen_root_element = False
        is_first_element = True

        self.last_valid_offset = cur_offset

        while True:
            if self.infile.tell() == self.unpacked_size:
                break

            self.last_valid_offset = self.infile.tell()

            # read relevant spare data.
            self.infile.seek(chunk_size, os.SEEK_CUR)

            # read the sequence number
            spare_bytes = self.infile.read(4)
            sequence_number = int.from_bytes(spare_bytes, byteorder=self.byteorder)

            # skip padding chunks
            if sequence_number == 0xffffffff:
                self.infile.seek(self.last_valid_offset + chunk_size + spare_size)
                continue

            # read the object id
            spare_bytes = self.infile.read(4)
            object_id = int.from_bytes(spare_bytes, byteorder=self.byteorder)

            # read the chunk id
            spare_bytes = self.infile.read(4)
            chunk_id = int.from_bytes(spare_bytes, byteorder=self.byteorder)

            # first check if the relevant info is stored in an inband tag
            # or in a normal tag. Inbound tags are described in the YAFFS2
            # code in the file yaffs_packedtags2.c
            #
            # For inbound tags some data (object id, chunk id) are
            # mixed with the actual data, so extract them first.
            if chunk_id & EXTRA_HEADER_INFO_FLAG == EXTRA_HEADER_INFO_FLAG:
                # store the original chunk_id as it will be needed later
                orig_chunk_id = chunk_id

                # extract the object_id
                object_id = object_id & ~EXTRA_OBJECT_TYPE_MASK

                # the chunk_id will have been changed ONLY for
                # the chunk with id 0 and not for any chunks
                # with data (files), so it is safe to simply
                # set the chunk_id to 0 here (new chunk).
                chunk_id = 0

            # read the chunk byte count
            spare_bytes = self.infile.read(4)
            byte_count = int.from_bytes(spare_bytes, byteorder=self.byteorder)

            # if it is a continuation of an existing object, then the
            # chunk id cannot be 0, as that is the header.
            if chunk_id != 0:
                object_id_to_latest_chunk[object_id] = chunk_id

                # jump to the offset of the chunk and write data. This needs
                # absolute offsets again. Dirty hack!

                # open the file in append mode. Unfortunately this means
                # that sendfile() cannot be used currently. From the man page:
                #
                # EINVAL out_fd has the O_APPEND flag set.  This is not currently
                # supported by sendfile().
                #
                # It looks like this will not be supported in the future
                unpacked_md = unpacked_mds[object_id]
                with open(unpacked_md.abs_file_path, 'ab') as outfile:
                    self.infile.seek(self.last_valid_offset)
                    outfile.write(self.infile.read(byte_count))
            else:
                last_open = None

                # store latest chunk id for this object
                object_id_to_latest_chunk[object_id] = chunk_id

                # jump to the offset of the chunk and analyze
                self.infile.seek(self.last_valid_offset)

                # object type
                object_bytes = self.infile.read(4)
                chunk_object_type = int.from_bytes(object_bytes, byteorder=self.byteorder)

                # read the parent object id
                parent_id_bytes = self.infile.read(4)
                parent_object_id = int.from_bytes(parent_id_bytes, byteorder=self.byteorder)

                if self.inband:
                    parent_object_id = orig_chunk_id & ~ALL_EXTRA_FLAG

                # skip the name checksum (2 bytes)
                self.infile.seek(2, os.SEEK_CUR)

                # object name
                # For some reason 2 extra bytes need to be read that have
                # been initialized to 0xff
                checkbytes = self.infile.read(YAFFS_MAX_NAME_LENGTH + 1 + 2)
                try:
                    object_name = os.path.normpath(checkbytes.split(b'\x00', 1)[0].decode())

                    # sanity check, needs more TODO
                    if os.path.isabs(object_name):
                        object_name = os.path.relpath(object_name, '/')
                except:
                    break

                # yst_mode
                stat_bytes = self.infile.read(4)
                mode = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                # stat information: uid, gid, atime, mtime, ctime
                stat_bytes = self.infile.read(4)
                uid = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                stat_bytes = self.infile.read(4)
                gid = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                stat_bytes = self.infile.read(4)
                atime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                stat_bytes = self.infile.read(4)
                mtime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                stat_bytes = self.infile.read(4)
                ctime = int.from_bytes(stat_bytes, byteorder=self.byteorder)

                # the object size. This only makes sense for files. The real
                # size depends on the "high" value as well.
                size_bytes = self.infile.read(4)
                object_size_low = int.from_bytes(size_bytes, byteorder=self.byteorder)

                # equiv_id, only makes sense for hard links
                equiv_bytes = self.infile.read(4)
                equiv_id = int.from_bytes(equiv_bytes, byteorder=self.byteorder)

                # alias, only makes sense for symlinks
                alias = self.infile.read(YAFFS_MAX_ALIAS_LENGTH + 1)

                # rdev, only for special files (block/char)
                rdev_bytes = self.infile.read(4)
                rdev = int.from_bytes(rdev_bytes, byteorder=self.byteorder)

                # skip some Windows specific structures
                self.infile.seek(24, os.SEEK_CUR)

                # skip some inband related structures
                self.infile.seek(8, os.SEEK_CUR)

                # object size high
                size_bytes = self.infile.read(4)
                object_size_high = int.from_bytes(size_bytes, byteorder=self.byteorder)

                # element 1 is special, but not every yaffs2 file system
                # seems to have element 1, so sometimes it needs to be
                # artificially added.
                if object_id == 1:
                    # skip the root element
                    self.infile.seek(self.last_valid_offset + chunk_size + spare_size)
                    continue

                file_path = pathlib.Path(self.object_id_to_name[parent_object_id]) / object_name

                if chunk_object_type == YAFFS_OBJECT_TYPE_FILE:
                    # first reconstruct the file size.
                    if object_size_high != 0xffffffff:
                        object_size = (object_size_high << 32) + object_size_low
                    else:
                        object_size = object_size_low

                    # write a stub file
                    # empty file
                    with meta_directory.unpack_regular_file(file_path) as (unpacked_md, f):
                        unpacked_mds[object_id] = unpacked_md

                    last_open = ''
                    last_open_size = object_size
                    previous_object_id = object_id
                elif chunk_object_type == YAFFS_OBJECT_TYPE_SYMLINK:
                    alias = alias.split(b'\x00', 1)[0].decode()
                    meta_directory.unpack_symlink(file_path, alias)
                elif chunk_object_type == YAFFS_OBJECT_TYPE_DIRECTORY:
                    # create the directory
                    meta_directory.unpack_directory(file_path)
                elif chunk_object_type == YAFFS_OBJECT_TYPE_HARDLINK:
                    linkname = self.object_id_to_name[equiv_id]
                    meta_directory.unpack_hardlink(file_path, linkname)
                elif chunk_object_type == YAFFS_OBJECT_TYPE_SPECIAL:
                    # no permissions to create special files,
                    # so don't create, but report instead. TODO
                    pass

                is_first_element = False
                data_unpacked = True

            if self.infile.tell() == self.unpacked_size:
                break

            # skip to the next chunk/spare
            self.infile.seek(self.last_valid_offset + chunk_size + spare_size)

        ''' TODO: find out what to do here
        # close any open files
        if last_open is not None:
            if object_id_to_latest_chunk[previous_object_id] == 0:
                if last_open_size != 0:
                    os.unlink(last_open.name)
                else:
                    fr = FileResult(self.fileresult, last_open_name, set())
                    unpacked_files.append(fr)
            else:
                fr = FileResult(self.fileresult, last_open_name, set())
                unpacked_files.append(fr)
        '''

        for unpacked_md in unpacked_mds.values():
            yield unpacked_md

    labels = ['yaffs2', 'filesystem']

    @property
    def metadata(self):
        return self.yaffs2_metadata
