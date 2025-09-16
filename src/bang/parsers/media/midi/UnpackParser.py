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

'''
Parse MIDI files.

Some documentation:

https://www.csie.ntu.edu.tw/~r92092/ref/midi/
'''

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

from . import vlq_base128_be
from . import standard_midi_file


class MidiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MThd')
    ]
    pretty_name = 'midi'

    def parse(self):
        try:
            self.data = standard_midi_file.StandardMidiFile.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

    labels = ['midi', 'audio']

    @property
    def metadata(self):
        metadata = {}

        # TODO: extract meta information from MIDI file
        return metadata
