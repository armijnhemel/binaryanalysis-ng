#!/usr/bin/env python3

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
# License, version 3, along with BANG. If not,
# see <http://www.gnu.org/licenses/>
#
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public
# License version 3
# SPDX-License-Identifier: AGPL-3.0-only

class BaseScanner:

    def __init__(self, dbconn, dbcursor, scanenvironment):
        self.scanenvironment = scanenvironment
        self.dbconn = dbconn
        self.dbcursor = dbcursor

    def should_scan(self, fileresult):
        return fileresult.labels.isdisjoint(set(self.ignore))

    def scan(self, fileresult):
        pass

