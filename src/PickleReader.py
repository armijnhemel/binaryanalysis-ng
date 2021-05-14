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

import pickle


class PickleReaderException(Exception):
    pass


class PickleReader:

    def __init__(self, scanenvironment):
        self.scanenvironment = scanenvironment

    def top_level_read(self, picklefilename):
        try:
            scanresult = pickle.load(picklefilename)
            return scanresult
        except Exception as e:
            raise PickleReaderException()

    def read(self, fileresult):

        # read a pickle with output data
        # The pickle contains:
        # * all available hashes
        # * labels
        # * byte count
        # * any extra data that might have been passed around

        picklefilename = self.scanenvironment.resultsdirectory / ("%s.pickle" % fileresult.get_hash('sha256'))
        # TODO: this is vulnerable to a race condition, replace with EAFP pattern
        if picklefilename.exists():
            try:
                pickleout = picklefilename.open('rb')
                fileresult = pickle.load(pickleout)
            except:
                raise PickleReaderException()
            finally:
                pickleout.close()
            return fileresult
        else:
            raise PickleReaderException()

