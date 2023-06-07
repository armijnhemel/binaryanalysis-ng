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

import pathlib

import dockerfile_parse

from bang.UnpackParser import UnpackParser, check_condition
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

            # as the contents are lazily evaluated force evaluation
            dockerfileparser.content
        except Exception as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.size

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['dockerfile']
    metadata = {}
