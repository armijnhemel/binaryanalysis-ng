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

import dockerfile_parse

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException


class DockerfileUnpackParser(UnpackParser):
    extensions = ['dockerfile', '.dockerfile']
    signatures = [
    ]
    pretty_name = 'dockerfile'

    def parse(self):
        # dockerfile_parse expects the file to be called "Dockerfile"
        # If not, it will assume that the file that is opened is a directory
        # containing a file "Dockerfile".
        # TODO: rename files in case they are not "*Dockerfile"
        try:
            dockerfileparser = dockerfile_parse.DockerfileParser(self.infile.name)

            # as contents are lazily evaluated by Kaitai force evaluation
            dockerfileparser.content
        except Exception as e:
            raise UnpackParserException(e.args) from e

        self.unpacked_size = self.infile.size

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['dockerfile']
    metadata = {}
