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

import os
import bangsignatures
from BaseScanner import *


# search files for license and forge references.
# https://en.wikipedia.org/wiki/Forge_(software)
class LicenseIdentifierScanner(BaseScanner):
    '''Search the presence of license identifiers in a file
       (URLs and other references)
       Search the presence of references to forges and other
       collaborative software development sites in a file
       (URLs and other references)
    '''

    context = ['file']
    ignore = ['archive', 'audio', 'audio', 'database', 'encrypted', 'filesystem', 'graphics', 'video']
    needsdatabase = False

    def scan(self, fileresult):
        # results is a dictionary, constructed as:
        returnres = {}
        licenseresults = {}
        forgeresults = {}

        seekbuf = bytearray(1000000)
        filename_full = self.scanenvironment.get_unpack_path_for_fileresult(fileresult)
        filesize = fileresult.filesize

        # open the file in binary mode
        checkfile = open(filename_full, 'rb')
        checkfile.seek(0)
        while True:
            bytesread = checkfile.readinto(seekbuf)
            for r in bangsignatures.licensereferences:
                for licenseref in bangsignatures.licensereferences[r]:
                    licenserefbytes = bytes(licenseref, 'utf-8')
                    if licenserefbytes in seekbuf:
                        if r not in licenseresults:
                            licenseresults[r] = []
                        licenseresults[r].append(licenseref)
            for r in bangsignatures.forgereferences:
                for forgeref in bangsignatures.forgereferences[r]:
                    forgerefbytes = bytes(forgeref, 'utf-8')
                    if forgerefbytes in seekbuf:
                        if r not in forgeresults:
                            forgeresults[r] = []
                        forgeresults[r].append(forgeref)
            if checkfile.tell() == filesize:
                break
            checkfile.seek(-50, os.SEEK_CUR)
        checkfile.close()

        returnres['key'] = 'license and forge identifiers'
        returnres['type'] = 'informational'
        returnres['value'] = {'license': licenseresults, 'forge': forgeresults}

        return returnres

