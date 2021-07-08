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
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import os
from reporter.elasticsearchreport import *

class AnalysisEnvironment:

    def __init__(self, runfilescans, logging, scanfilequeue,
                 processlock, checksumdict,
                ):
        """scanfilequeue: a Queue where files to scan will be fetched from
           processlock: a Lock object that guards access to shared objects
           checksumdict: a shared dictionary to store hashes of files to
                         prevent scans of duplicate files.
        """
        # TODO: init from options object
        self.logging = logging
        self.scanfilequeue = scanfilequeue
        self.processlock = processlock
        self.checksumdict = checksumdict
        self.runfilescans = runfilescans
        self.reporters = []

    def get_runfilescans(self):
        return self.runfilescans

    def unpack_path(self, fn):
        """Returns a path object containing the absolute path of the file in
        the unpack directory root.
        If fn is an absolute path, then fn will be returned.
        """
        return self.unpackdirectory / fn

    def get_unpack_path_for_fileresult(self, fr):
        """Returns the absolute path of the file in fileresult fr."""
        if fr.has_parent():
            return self.unpackdirectory / fr.filename
        else:
            return fr.filename

    def rel_unpack_path(self, fn):
        # TODO: check if fn starts with unpackdirectory to catch path traversal
        # in that case, return absolute path? but what about:
        # >>> os.path.relpath('xa/b/c/d/e',root)
        # '../../../home/tim/binaryanalysis-ng/src/xa/b/c/d/e'
        return os.path.relpath(fn, self.unpackdirectory)

    def tmp_path(self, fn):
        return os.path.join(self.temporarydirectory, fn)

    def rel_tmp_path(self, fn):
        return os.path.relpath(fn, self.temporarydirectory)
