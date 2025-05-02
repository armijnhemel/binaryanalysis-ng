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

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
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
        check_condition(self.data.index_offset <= self.infile.size, "index offset outside of file")
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

    labels = ['doom', 'wad', 'resource']
    metadata = {}
