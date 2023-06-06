#!/usr/bin/env python3

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
# Copyright 2018-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import sys
import os
import shutil
import tempfile
import re
import pathlib
import email.parser

# some external packages that are needed
import dockerfile_parse


# Docker file parsing, only works on whole Dockerfiles
def unpack_dockerfile(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Dockerfile.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    renamed = False
    if not filename_full.name.endswith('Dockerfile'):
        dockerdir = pathlib.Path(tempfile.mkdtemp(dir=scanenvironment.temporarydirectory))
        shutil.copy(filename_full, dockerdir / 'Dockerfile')
        dockerfileparser = dockerfile_parse.DockerfileParser(str(dockerdir / 'Dockerfile'))
        renamed = True
    else:
        dockerfileparser = dockerfile_parse.DockerfileParser(str(filename_full))

    try:
        dfcontent = dockerfileparser.content
    except Exception:
        if renamed:
            shutil.rmtree(dockerdir)
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Dockerfile'}
        return {'status': False, 'error': unpackingerror}

    labels.append('dockerfile')
    if renamed:
        shutil.rmtree(dockerdir)

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_dockerfile.extensions = ['dockerfile', '.dockerfile']
unpack_dockerfile.pretty = 'dockerfile'
#unpack_dockerfile.scope = 'text'


# verify TRANS.TBL files
# https://en.wikipedia.org/wiki/TRANS.TBL
def unpack_trans_tbl(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a TRANS.TBL file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    shadowentries = []

    # open the file in text mode
    try:
        checkfile = open(filename_full, 'r')
        for line in checkfile:
            linesplits = line.strip().split()
            if len(linesplits) < 3:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'not enough data for entry'}
                return {'status': False, 'error': unpackingerror}
            # check if the line has the correct file type indicator:
            # * file
            # * directory
            # * link
            # * fifo
            # (missing: sockets and device files)
            if linesplits[0] not in ['F', 'D', 'L', 'P']:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'wrong file type indicator'}
                return {'status': False, 'error': unpackingerror}
    except UnicodeDecodeError:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for entry'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('trans.tbl')
    labels.append('resource')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_trans_tbl.extensions = ['trans.tbl']
unpack_trans_tbl.pretty = 'trans.tbl'
