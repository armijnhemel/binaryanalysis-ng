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
from kaitaistruct import ValidationNotEqualError
from . import doom_wad

from UnpackParser import WrappedUnpackParser
from banggames import unpack_doom_wad

#class DoomWadUnpackParser(UnpackParser):
class DoomWadUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_doom_wad(fileresult, scan_environment, offset, unpack_dir)

    # http://web.archive.org/web/20090530112359/http://www.gamers.org/dhs/helpdocs/dmsp1666.html
    # chapter 2
    def parse(self):
        try:
            self.data = doom_wad.DoomWad.from_io(self.infile)
        # TODO: decide what exceptions to catch
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.num_index_entries > 0, "no lumps defined")

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.index_offset + self.data.num_index_entries * 16
        for i in self.data.index:
            self.unpacked_size = max(self.unpacked_size, i.offset + i.size)

    def set_metadata_and_labels(self):
        self.unpack_results.set_labels(['doom', 'wad', 'resource'])
        self.unpack_results.set_metadata({})
