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
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import doom_wad

class DoomWadUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    # http://web.archive.org/web/20090530112359/http://www.gamers.org/dhs/helpdocs/dmsp1666.html
    # chapter 2
    def parse(self):
        try:
            self.data = doom_wad.DoomWad.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)
        # this is a bit of an ugly hack to detect if the file has been
        # truncated or corrupted. In certain cases (like when scanning the
        # 'magic' database) it could be that the offset would be bigger
        # than the file itself and there would be hundreds of millions of
        # index entries for which the generated code would first try to create
        # an IndexEntry() object leading to an out of memory issue.
        filesize = self.fileresult.filesize
        check_condition(self.data.index_offset <= filesize, "index offset outside of file")
        check_condition(self.data.num_index_entries > 0, "no lumps defined")

        # another ugly hack to prevent ASCII decoding errors
        # (example: when scanning mime.cache)
        try:
            for i in self.data.index:
                pass
        except Exception as e:
            raise UnpackParserException(e.args)

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.index_offset + self.data.num_index_entries * 16
        for i in self.data.index:
            self.unpacked_size = max(self.unpacked_size, i.offset + i.size)

    def set_metadata_and_labels(self):
        self.unpack_results.set_labels(['doom', 'wad', 'resource'])
        self.unpack_results.set_metadata({})
