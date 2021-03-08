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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import json

class JsonReporter:

    def __init__(self, scanenvironment):
        self.scanenvironment = scanenvironment

    def report(self, fileresult):

        resultout = {}

        if hasattr(fileresult,'byte_counter'):
            resultout['bytecount'] = sorted(fileresult.byte_counter.get().items())

        for a, h in fileresult.get_hashresult().items():
            resultout[a] = h

        resultout['labels'] = list(fileresult.labels)
        if fileresult.metadata is not None:
            resultout['metadata'] = fileresult.metadata

        jsonfilename = self.scanenvironment.resultsdirectory / ("%s.json" % fileresult.get_hash('sha256'))
        if not jsonfilename.exists():
            jsonout = jsonfilename.open('w')
            json.dump(resultout, jsonout, indent=4)
            jsonout.close()

