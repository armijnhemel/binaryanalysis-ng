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

from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_yaffs2

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

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
# (4080, 16) is an example of a common size for inline tags
CHUNKS_AND_SPARES = [(2048, 64), (1024, 32), (4096, 128), (8192, 256),
                     (8192, 448), (512, 16), (4096, 16), (4080, 16)]

class Yaffs2UnpackParser(WrappedUnpackParser):
#class Yaffs2UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        (0, b'\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff'),
        #(0, b'\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff'),
        #(0, b'\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff')
    ]
    pretty_name = 'yaffs2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_yaffs2(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        # then try to read the file system for various chunk/spare
        # combinations. The metadata is in the 'spare' part.
        for (chunk_size, spare_size) in CHUNKS_AND_SPARES:
            # seek to the original offset
            self.infile.seek(offset)

            # keep a mapping of object ids to latest chunk id
            objectid_to_latest_chunk = {}

            # keep a mapping of object ids to type
            objectid_to_type = {}

            # keep a mapping of object ids to name
            objectid_to_name = {}

            # keep a mapping of object ids to file size
            # for sanity checks
            objectid_to_size = {}

            # store the last open file for an object
            last_open = None
            last_open_name = None
            last_open_size = 0
            previous_objectid = 0

            # store if element with object id 1 has been seen. Most, but not all,
            # YAFFS2 images have this as a separate chunk.
            seen_root_element = False
            is_first_element = True

            # store if this is an inband image
            inband = False



    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['yaffs2', 'filesystem']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
