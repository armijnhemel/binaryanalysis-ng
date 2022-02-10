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

'''
Parse MIDI files.

Some documentation:

https://www.csie.ntu.edu.tw/~r92092/ref/midi/
'''

import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
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
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'midi', 'audio' ]
        metadata = {}
        pngtexts = []

        # TODO: extract meta information from MIDI file

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
