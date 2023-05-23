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
import configparser
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


# Python PKG-INFO file parsing
# Described in PEP-566:
# https://www.python.org/dev/peps/pep-0566/
def unpack_python_pkginfo(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Python PKG-INFO file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    validversions = ['1.0', '1.1', '1.2', '2.1']
    strictcheck = False

    # the various PEP specifications define mandatory items but in
    # practice these are not followed: many mandatory items are
    # simply not present and items defined in later versions are.
    # This could be because the PEPs are a bit ambigious and/or
    # tools/packagers are sloppy.

    # https://www.python.org/dev/peps/pep-0241/
    mandatory10 = ['Metadata-Version',
                   'Name',
                   'Version',
                   'Platform',
                   'Summary',
                   'Author-email',
                   'License']

    optional10 = ['Description',
                  'Keywords',
                  'Home-page',
                  'Author']

    # https://www.python.org/dev/peps/pep-0314/
    mandatory11 = ['Metadata-Version',
                   'Name',
                   'Version',
                   'Platform',
                   'Supported-Platform',
                   'Summary',
                   'Download-URL',
                   'Author-email',
                   'License',
                   'Classifier',
                   'Requires',
                   'Provides',
                   'Obsoletes']

    optional11 = ['Description',
                  'Keywords',
                  'Home-page',
                  'Author']

    # version 1.2 and 2.1 have the same mandatory fields
    # https://www.python.org/dev/peps/pep-0345/
    # https://www.python.org/dev/peps/pep-0566/
    mandatory12 = ['Metadata-Version',
                   'Name',
                   'Version',
                   'Platform',
                   'Supported-Platform',
                   'Summary',
                   'Download-URL',
                   'Classifier',
                   'Requires-Dist',
                   'Provides-Dist',
                   'Obsoletes-Dist',
                   'Requires-Python',
                   'Requires-External',
                   'Project-URL']

    optional12 = ['Description',
                  'Keywords',
                  'Home-page',
                  'Author',
                  'Author-email',
                  'Maintainer',
                  'Maintainer-email',
                  'License']

    optional21 = ['Description',
                  'Keywords',
                  'Home-page',
                  'Author',
                  'Author-email',
                  'Maintainer',
                  'Maintainer-email',
                  'License',
                  'Description-Content-Type',
                  'Provides-Extra']

    alloptional = set()
    alloptional.update(optional10)
    alloptional.update(optional11)
    alloptional.update(optional12)
    alloptional.update(optional21)

    # open the file in text only mode
    try:
        checkfile = open(filename_full, 'r')
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Python PKG-INFO'}
        return {'status': False, 'error': unpackingerror}

    try:
        headerparser = email.parser.HeaderParser()
        headers = headerparser.parse(checkfile)
        checkfile.close()
    except Exception:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Python PKG-INFO'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    # then some sanity checks
    if 'Metadata-Version' not in headers:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Metadata-Version missing'}
        return {'status': False, 'error': unpackingerror}

    metadataversion = headers['Metadata-Version']

    if metadataversion not in validversions:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'Metadata-Version invalid'}
        return {'status': False, 'error': unpackingerror}

    # keep track which mandatory items are missing
    missing = set()

    # keep track of which items are in the wrong version
    wrongversion = set()

    if metadataversion == '1.0':
        if strictcheck:
            for i in mandatory10:
                if i not in headers:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': '%s missing' % i}
                    return {'status': False, 'error': unpackingerror}
        for i in headers:
            if not (i in mandatory10 or i in optional10):
                if i in alloptional:
                    wrongversion.add(i)
                else:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'undefined tag: %s' % i}
                    return {'status': False, 'error': unpackingerror}
    elif metadataversion == '1.1':
        if strictcheck:
            for i in mandatory11:
                if i not in headers:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': '%s missing' % i}
                    return {'status': False, 'error': unpackingerror}
        for i in headers:
            if not (i in mandatory11 or i in optional11):
                if i in alloptional:
                    wrongversion.add(i)
                else:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'undefined tag: %s' % i}
                    return {'status': False, 'error': unpackingerror}
    elif metadataversion == '1.2':
        if strictcheck:
            for i in mandatory12:
                if i not in headers:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': '%s missing' % i}
                    return {'status': False, 'error': unpackingerror}
        for i in headers:
            if not (i in mandatory12 or i in optional12 or i in alloptional):
                if i in alloptional:
                    wrongversion.add(i)
                else:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'undefined tag: %s' % i}
                    return {'status': False, 'error': unpackingerror}
    elif metadataversion == '2.1':
        if strictcheck:
            for i in mandatory12:
                if i not in headers:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': '%s missing' % i}
                    return {'status': False, 'error': unpackingerror}
        for i in headers:
            if not (i in mandatory12 or i in optional21):
                if i in alloptional:
                    wrongversion.add(i)
                else:
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'undefined tag: %s' % i}
                    return {'status': False, 'error': unpackingerror}

    labels.append('python pkg-info')
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_python_pkginfo.extensions = ['.pkginfo']
unpack_python_pkginfo.pretty = 'pkginfo'


# Linux Software Map file
# https://www.ibiblio.org/pub/Linux/docs/linux-software-map/lsm-template (version 3)
# http://www.ibiblio.org/pub/linux/LSM-TEMPLATE.html (version 4)
def unpack_lsm(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Linux Software Map file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # assume it is a text file
    try:
        checkfile = open(filename_full, 'r')
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    dataunpacked = False
    mandatoryfields = ['Title', 'Version', 'Entered-date',
                       'Description', 'Author', 'Primary-site']

    allfields = ['Title', 'Version', 'Entered-date', 'Description', 'Keywords',
                 'Author', 'Maintained-by', 'Primary-site', 'Alternate-site',
                 'Original-site', 'Platforms', 'Copying-policy']

    seenfields = set()

    try:
        firstline = True
        endseen = False
        for i in checkfile:
            if endseen:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'trailing data'}
                return {'status': False, 'error': unpackingerror}
            if i.strip() == '':
                continue
            if firstline:
                if i.rstrip() != 'Begin3' and i.rstrip() != 'Begin4':
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid first line'}
                    return {'status': False, 'error': unpackingerror}
                firstline = False
                continue
            if i.rstrip() == 'End':
                endseen = True
                continue
            if i.startswith(' ') or i.startswith('\t'):
                continue
            linesplit = i.rstrip().split(':', 1)
            if len(linesplit) != 2:
                break

            # then the key type
            lsmfield = linesplit[0]
            if lsmfield not in allfields:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid LSM field %s' % lsmfield}
                return {'status': False, 'error': unpackingerror}
            seenfields.add(lsmfield)
            dataunpacked = True
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid Linux Software Map file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no data unpacked'}
        return {'status': False, 'error': unpackingerror}

    if not endseen:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no end field'}
        return {'status': False, 'error': unpackingerror}

    for i in mandatoryfields:
        if i not in seenfields:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'mandatory field %s missing' % i}
            return {'status': False, 'error': unpackingerror}

    labels.append('linux software map')
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_lsm.extensions = ['.lsm']
unpack_lsm.pretty = 'lsm'


# simple, no frills, non-authorative way to see if text files are
# scripts using a few simple checks, such as the shebang line and
# a few more simple checks.
def unpack_script(fileresult, scanenvironment, offset, unpackdir):
    '''Simple sanity checks to see a file is possibly a script'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file in text mode
    checkfile = open(filename_full, 'r')

    # some very basic rules:
    # 1. check the first line to see if #! is found
    # 2. parse the first line to see if the name of an interpreter
    #    is found
    # 3. look at the extension
    checkline = checkfile.readline()
    if '#!' in checkline:
        if filename_full.suffix.lower() == '.py':
            if 'python' in checkline.strip():
                checkfile.close()
                labels.append('script')
                labels.append('python')
                unpackedsize = filesize
                return {'status': True, 'length': unpackedsize,
                        'labels': labels,
                        'filesandlabels': unpackedfilesandlabels}
        elif filename_full.suffix.lower() == '.pl':
            if 'perl' in checkline.strip():
                checkfile.close()
                labels.append('script')
                labels.append('perl')
                unpackedsize = filesize
                return {'status': True, 'length': unpackedsize,
                        'labels': labels,
                        'filesandlabels': unpackedfilesandlabels}
        elif filename_full.suffix.lower() == '.sh':
            if '/bash' in checkline.strip():
                checkfile.close()
                labels.append('script')
                labels.append('bash')
                unpackedsize = filesize
                return {'status': True, 'length': unpackedsize,
                        'labels': labels,
                        'filesandlabels': unpackedfilesandlabels}
            if '/sh' in checkline.strip():
                checkfile.close()
                labels.append('script')
                labels.append('shell')
                unpackedsize = filesize
                return {'status': True, 'length': unpackedsize,
                        'labels': labels,
                        'filesandlabels': unpackedfilesandlabels}
    else:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not determine script status'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()
    unpackingerror = {'offset': offset, 'fatal': False,
                      'reason': 'could not determine script status'}
    return {'status': False, 'error': unpackingerror}

unpack_script.pretty = 'script'
unpack_script.scope = 'text'


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


def unpack_ini(fileresult, scanenvironment, offset, unpackdir):
    '''Verify an INI file '''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    iniconfig = configparser.ConfigParser()
    configfile = open(filename_full, 'r')

    try:
        iniconfig.read_file(configfile)
        configfile.close()
    except:
        # could include:
        # configparser.MissingSectionHeaderError
        # configparser.DuplicateOptionErrorr
        #  configparser.ParsingError
        configfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid INI file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize
    labels.append('ini')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ini.extensions = ['.ini']
unpack_ini.pretty = 'ini'


# file subversion/libsvn_subr/hash.c in Subversion source code
def unpack_subversion_hash(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Subversion hash file '''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # open the file in text only mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid subversion hash file'}
        return {'status': False, 'error': unpackingerror}

    bytesread = 0
    nextaction = 'new'
    localbytesread = 0
    try:
        # simple state machine
        for line in checkfile:
            localbytesread += len(line)
            if nextaction == 'filename':
                lineres = re.match(r'[\w\d\!\./-]+$', line.rstrip())
                if lineres is not None:
                    nextaction = 'new'
                    continue
                nextaction = 'new'
            if nextaction == 'new':
                lineres = re.match(r'K (\d+)$', line.rstrip())
                if lineres is None:
                    break
                linelength = int(lineres.groups()[0])
                nextaction = 'data'
            elif nextaction == 'data':
                if linelength != len(line) - 1:
                    break
                nextaction = 'value'
            elif nextaction == 'value':
                if line.rstrip() == 'END':
                    bytesread += localbytesread
                    # reset a few values
                    localbytesread = 0
                    nextaction = 'filename'
                else:
                    lineres = re.match(r'V (\d+)$', line.rstrip())
                    if lineres is None:
                        break
                    linelength = int(lineres.groups()[0])
                    nextaction = 'data'
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid subversion hash file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    if bytesread != filesize:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not a valid subversion hash file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize
    labels.append('subversion hash')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_subversion_hash.extensions = ['wcprops']
unpack_subversion_hash.pretty = 'subversion_hash'
