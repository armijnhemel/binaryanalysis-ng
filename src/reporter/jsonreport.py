# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3, as published by the Free Software Foundation.
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
import copy

class JsonReporter:
    def __init__(self, reportfile):
        self.reportfile = reportfile
    def report(self,scanresult):
        # copy scanresult because json cannot serialize datetime objects by itself
        sr = copy.deepcopy(scanresult)
        sr['session']['start'] = sr['session']['start'].isoformat()
        sr['session']['stop'] = sr['session']['stop'].isoformat()

        # store the scan uuid in URN (RFC 4122) form
        sr['session']['uuid'] = sr['session']['uuid'].urn
        json.dump(sr, self.reportfile, indent=4)


