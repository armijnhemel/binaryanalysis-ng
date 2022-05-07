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
import binascii
import tempfile
import base64
import re
import pathlib
import configparser
import email.parser

# some external packages that are needed
import tinycss2
import dockerfile_parse
import icalendar

from FileResult import *


# For now it is assumed that only files that are completely text
# files can be CSS files
def unpack_css(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a CSS file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    isopened = False

    # open the file in text only mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid CSS file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(0)

    # read the file: Python's text reader will fairly quickly
    # detect the binary files, so not a lot of extra data will
    # be read.
    try:
        cssbytes = checkfile.read()
    except:
        if isopened:
            checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}
    checkfile.close()

    try:
        cssres = tinycss2.parse_stylesheet(cssbytes)
    except Exception:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'could not parse CSS'}
        return {'status': False, 'error': unpackingerror}

    dataunpacked = False
    for c in cssres:
        if type(c) == tinycss2.ast.ParseError:
            unpackingerror = {'offset': offset, 'fatal': False,
                              'reason': 'CSS parse error'}
            return {'status': False, 'error': unpackingerror}
        if type(c) == tinycss2.ast.WhitespaceToken:
            pass
        else:
            dataunpacked = True

    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no CSS unpacked'}
        return {'status': False, 'error': unpackingerror}

    labels.append('css')

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_css.extensions = ['.css']
unpack_css.pretty = 'css'
unpack_css.scope = 'text'


# parse Java/Android manifest files, assume text only for now
# https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Manifest_Specification
def unpack_java_manifest(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Java manifest file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    valid_attributes = set(['Name',
                            'Manifest-Version',
                            'Created-By',
                            'Signature-Version',
                            'Class-Path',
                            'Main-Class',
                            'Extension-List',
                            'Extension-Name',
                            'Implementation-Title',
                            'Implementation-Version',
                            'Implementation-Vendor',
                            'Implementation-Vendor-Id ',
                            'Implementation-URL',
                            'Specification-Title',
                            'Specification-Version',
                            'Specification-Vendor',
                            'Sealed',
                            'Content-Type',
                            'Java-Bean',
                            'Magic'])

    extension_attributes = ['-Extension-Name',
                            '-Specification-Version',
                            '-Implementation-Version',
                            '-Implementation-Vendor-Id',
                            '-Implementation-URL',
                            '-Digest-Manifest',
                            '-Digest-Manifest-Main-Attributes']

    custom_attributes = ['Built-By', 'Ant-Version']
    android_attributes = ['X-Android-APK-Signed']
    bnd_attributes = ['Bnd-LastModified', 'Bundle-License',
                      'Bundle-ManifestVersion', 'Bundle-Name',
                      'Bundle-RequiredExecutionEnvironment',
                      'Bundle-SymbolicName', 'Bundle-Vendor',
                      'Bundle-Version', 'DSTAMP', 'DynamicImport-Package',
                      'Export-Package', 'Extension-name', 'Import-Package',
                      'Include-Resource', 'TODAY', 'Tool', 'TSTAMP']

    isopened = False

    # open the file in text only mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(0)
    manifestlinesseen = False
    isandroid = False

    try:
        for i in checkfile:
            # skip empty lines
            if i.strip() == '':
                continue
            # regular lines need to have : in them, unless they
            # are a continuation of a previous line
            if ':' not in i or i.startswith(' '):
                if re.match(r'\s+[\"; \-\.,\w\d/=:]+$', i.rstrip()) is not None:
                    continue
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid manifest line'}
                return {'status': False, 'error': unpackingerror}
            manifestattribute = i.strip().split(':', 1)[0].strip()
            if manifestattribute in valid_attributes:
                manifestlinesseen = True
                continue
            # check the digest values
            if manifestattribute in ['SHA1-Digest', 'SHA-256-Digest']:
                digest = i.strip().split(':', 1)[1].strip()
                try:
                    base64.b64decode(digest)
                except Exception:
                    checkfile.close()
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid digest'}
                    return {'status': False, 'error': unpackingerror}
                continue
            # check a few exceptions
            validextensionattribute = False
            customattribute = False
            androidattribute = False
            bndattribute = False
            for a in extension_attributes:
                if manifestattribute.endswith(a):
                    validextensionattribute = True
                    break
            for a in custom_attributes:
                if manifestattribute.endswith(a):
                    customattribute = True
                    break
            for a in android_attributes:
                if manifestattribute.endswith(a):
                    androidattribute = True
                    isandroid = True
                    break
            for a in bnd_attributes:
                if manifestattribute.endswith(a):
                    bndattribute = True
                    break
            if not (validextensionattribute or customattribute or androidattribute or bndattribute):
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid manifest line'}
                return {'status': False, 'error': unpackingerror}
    except:
        if isopened:
            checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}
    checkfile.close()

    if not manifestlinesseen:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'no valid manifest lines seen'}
        return {'status': False, 'error': unpackingerror}

    labels.append('text')
    labels.append('javamanifest')
    if isandroid:
        labels.append('android')

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_java_manifest.extensions = ['manifest.mf', '.sf']
unpack_java_manifest.pretty = 'javamanifest'
unpack_java_manifest.scope = 'text'


# Kernel configuration files that are embedded in Linux kernel
# images: text only
def unpack_kernel_config(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Linux kernel configuration file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # store some of the metadata for later use
    kernelconfig = {}
    kernelres = {}

    # first header line, was changed in Linux kernel commit
    # e54e692ba613c2170c66ce36a3791c009680af08
    headerre = re.compile(r'# Automatically generated make config: don\'t edit$')
    headerre_alt = re.compile(r'# Automatically generated file; DO NOT EDIT.$')

    headerre2 = re.compile(r'# Linux kernel version: ([\d\.]+)$')
    headerre2_alt = re.compile(r'# Linux/[\w\d\-_]+ ([\d\w\.\-_]+) Kernel Configuration$')
    headerre3 = re.compile(r'# (\w{3} \w{3} [\d ]+ \d{2}:\d{2}:\d{2} \d{4})$')
    headerre4 = re.compile(r'# Compiler: ([\w\d\.\-() ]+)$')

    # regular expression for the configuration header lines
    configheaderre = re.compile(r'# [\w\d/\-;:\. ,()&+]+$')

    # regular expressions for the lines with configuration
    configre = re.compile(r'# CONFIG_[\w\d_]+ is not set$')
    configre2 = re.compile(r'(CONFIG_[\w\d_]+)=([ynm])$')
    configre3 = re.compile(r'(CONFIG_[\w\d_]+)=([\w\d"\-/\.$()+]+$)')

    # open the file in text only mode
    checkfile = open(filename_full, 'r')

    headerfound = False
    kernelconfigfound = False

    # first there is a header
    # followed by sections
    # followed by configuration statements
    for i in checkfile:
        # skip empty lines
        if i.strip() == '':
            continue
        # skip empty comment lines
        if i.strip() == '#':
            continue
        linematched = False
        if i.strip().startswith('#'):
            if configre.match(i.strip()) is not None:
                linematched = True
                kernelconfigfound = True
            else:
                if not headerfound:
                    if headerre.match(i.strip()) is not None:
                        linematched = True
                    elif headerre_alt.match(i.strip()) is not None:
                        linematched = True
                    elif headerre2.match(i.strip()) is not None:
                        kernelversion = headerre2.match(i.strip()).groups()[0]
                        kernelres['version'] = kernelversion
                        linematched = True
                    elif headerre2_alt.match(i.strip()) is not None:
                        kernelversion = headerre2_alt.match(i.strip()).groups()[0]
                        kernelres['version'] = kernelversion
                        linematched = True
                    elif headerre3.match(i.strip()) is not None:
                        kerneldate = headerre3.match(i.strip()).groups()[0]
                        kernelres['date'] = kerneldate
                        linematched = True
                        headerfound = True
                    elif headerre4.match(i.strip()) is not None:
                        compiler = headerre4.match(i.strip()).groups()[0]
                        kernelres['compiler'] = compiler
                        linematched = True
                        headerfound = True
                else:
                    if configheaderre.match(i.strip()) is not None:
                        linematched = True
        else:
            if configre2.match(i.strip()) is None:
                if configre3.match(i.strip()) is not None:
                    (conf, val) = configre3.match(i.strip()).groups()
                    kernelconfig[conf] = val
                    linematched = True
                    kernelconfigfound = True
            else:
                (conf, val) = configre2.match(i.strip()).groups()
                kernelconfig[conf] = val
                linematched = True
                kernelconfigfound = True
        if not linematched:
            break

    checkfile.close()

    if not kernelconfigfound:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not kernel configuration file'}
        return {'status': False, 'error': unpackingerror}

    labels.append('text')
    labels.append('kernel configuration')

    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_kernel_config.pretty = 'kernelconfig'
unpack_kernel_config.scope = 'text'


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


# SSH known hosts file
# man 8 sshd
def unpack_ssh_known_hosts(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a SSH known hosts file.'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    # valid key types
    keytypes = ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521", "ssh-ed25519", "ssh-dss",
                "ssh-rsa"]

    # assume it is a text file
    try:
        checkfile = open(filename_full, 'r')
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid ssh known hosts file'}
        return {'status': False, 'error': unpackingerror}

    dataunpacked = False

    try:
        for i in checkfile:
            if i.startswith('#'):
                continue
            if i.strip == '':
                continue
            linesplit = i.strip().split(' ')
            # now process each element
            linesplitcounter = 0
            if linesplit[0].startswith('@'):
                if not (linesplit[0] == '@cert-authority' or linesplit[0] == '@revoked'):
                    unpackingerror = {'offset': offset, 'fatal': False,
                                      'reason': 'invalid marker'}
                linesplitcounter += 1
            # extra sanity check: there have to be at least three fields
            if len(linesplit) - linesplitcounter < 3:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'not enough fields'}
                return {'status': False, 'error': unpackingerror}

            # first the hostnames field
            # TODO: more checks
            hostnamesfield = linesplit[linesplitcounter]
            hostnames = hostnamesfield.split(',')

            # then the key type
            keytype = linesplit[linesplitcounter+1]
            if keytype not in keytypes:
                # TODO: why not mark the key as unknown and return a result?
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid key type'}
                return {'status': False, 'error': unpackingerror}
            # then the key, base64 encoded
            try:
                sshkey = base64.standard_b64decode(linesplit[linesplitcounter+2])
            except:
                checkfile.close()
                unpackingerror = {'offset': offset, 'fatal': False,
                                  'reason': 'invalid key (not base64)'}
                return {'status': False, 'error': unpackingerror}
            # ignore any comments
            dataunpacked = True
    except:
        checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid ssh known hosts file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    if not dataunpacked:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a valid ssh known hosts file'}
        return {'status': False, 'error': unpackingerror}

    labels.append('ssh known hosts')
    return {'status': True, 'length': filesize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ssh_known_hosts.extensions = ['ssh_known_hosts', 'known_hosts']
unpack_ssh_known_hosts.pretty = 'ssh_known_hosts'


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


# verify various types of Unix passwd files
# man 5 passwd
# https://www.freebsd.org/cgi/man.cgi?query=passwd&sektion=5
def unpack_passwd(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Unix password file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    passwdentries = []

    passwdfieldsallowed = [7, 10]
    foundlen = 0

    # open the file
    try:
        checkfile = open(filename_full, 'r')
        for l in checkfile:
            linesplits = l.strip().split(':')
            if foundlen == 0:
                if len(linesplits) in passwdfieldsallowed:
                    foundlen = len(linesplits)
            if len(linesplits) != foundlen:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid passwd file entry'}
                return {'status': False, 'error': unpackingerror}
            try:
                uid = int(linesplits[2])
            except ValueError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid UID in passwd file entry'}
                return {'status': False, 'error': unpackingerror}
            try:
                gid = int(linesplits[3])
            except ValueError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid GID in passwd file entry'}
                return {'status': False, 'error': unpackingerror}
            passwdentry = {}
            passwdentry['name'] = linesplits[0]
            passwdentry['passwd'] = linesplits[1]
            passwdentry['uid'] = uid
            passwdentry['gid'] = gid

            if foundlen == 7:
                passwdentry['gecos'] = linesplits[4]
                passwdentry['directory'] = linesplits[5]
                passwdentry['shell'] = linesplits[6]
            elif foundlen == 10:
                passwdentry['class'] = linesplits[4]
                passwdentry['change'] = linesplits[5]
                passwdentry['expire'] = linesplits[6]
                passwdentry['gecos'] = linesplits[7]
                passwdentry['directory'] = linesplits[8]
                passwdentry['shell'] = linesplits[9]
            passwdentries.append(passwdentry)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for entry'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('passwd')
    if foundlen == 10:
        labels.append('bsd passwd')
    else:
        labels.append('linux passwd')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_passwd.extensions = ['passwd']
unpack_passwd.pretty = 'passwd'


# verify Unix group files
# man 5 group
def unpack_group(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Unix group file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    groupentries = []

    # open the file
    try:
        checkfile = open(filename_full, 'r')
        for l in checkfile:
            linesplits = l.strip().split(':')
            if len(linesplits) != 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid group file entry'}
                return {'status': False, 'error': unpackingerror}
            if linesplits[0] == '':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid group name'}
                return {'status': False, 'error': unpackingerror}
            try:
                groupid = int(linesplits[2])
            except ValueError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid GID in entry'}
                return {'status': False, 'error': unpackingerror}
            if linesplits[3] != '':
                members = linesplits[3].split(',')
            else:
                members = []

            groupentry = {}
            groupentry['name'] = linesplits[0]
            groupentry['passwd'] = linesplits[1]
            groupentry['gid'] = groupid
            groupentry['members'] = members
            groupentries.append(groupentry)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for entry'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('group')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_group.extensions = ['group']
unpack_group.pretty = 'group'


# verify Unix shadow files
# man 5 shadow
def unpack_shadow(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Unix shadow file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    shadowentries = []

    # open the file
    try:
        checkfile = open(filename_full, 'r')
        for line in checkfile:
            linesplits = line.strip().split(':')
            if len(linesplits) != 9:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid shadow file entry'}
                return {'status': False, 'error': unpackingerror}
            try:
                datechanged = int(linesplits[2])
            except ValueError:
                if linesplits[2] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid date changed in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            try:
                minpasswdage = int(linesplits[3])
            except ValueError:
                if linesplits[3] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid minimum passwd age in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            try:
                maxpasswdage = int(linesplits[4])
            except ValueError:
                if linesplits[4] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid maximum passwd age in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            try:
                passwdwarning = int(linesplits[5])
            except ValueError:
                if linesplits[5] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid passwd warning period in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            try:
                passwdwarning = int(linesplits[6])
            except ValueError:
                if linesplits[6] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid passwd inactivity period in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            try:
                accountexpiration = int(linesplits[7])
            except ValueError:
                if linesplits[7] != '':
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid account expiration period in shadow entry'}
                    return {'status': False, 'error': unpackingerror}
            shadowentry = {}
            shadowentry['name'] = linesplits[0]
            shadowentry['passwd'] = linesplits[1]
            shadowentries.append(shadowentry)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for entry'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('shadow')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_shadow.extensions = ['shadow']
unpack_shadow.pretty = 'shadow'


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


# verify Linux fstab files
# man 5 fstab
def unpack_fstab(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Linux fstab file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    fstabentries = []

    foundlen = 0
    isopened = False

    # open the file in text mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
        for l in checkfile:
            # skip blank lines
            if l.strip() == '':
                continue
            # skip comments
            if l.startswith('#'):
                continue
            linesplits = l.strip().split()
            if len(linesplits) < 4:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'not enough data for fstab entry'}
                return {'status': False, 'error': unpackingerror}
            if len(linesplits) > 6:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'too much data for fstab entry'}
                return {'status': False, 'error': unpackingerror}
            fstabentry = {}
            fstabentry['device'] = linesplits[0]
            fstabentry['path'] = linesplits[1]
            fstabentry['fstype'] = linesplits[2]
            fstabentry['options'] = linesplits[3].split(',')
            if len(linesplits) > 4:
                fstabentry['frequency'] = linesplits[4]
            if len(linesplits) > 5:
                fstabentry['pass'] = linesplits[5]
            fstabentries.append(fstabentry)
    except:
        if isopened:
            checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong encoding'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('fstab')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_fstab.extensions = ['fstab']
unpack_fstab.pretty = 'fstab'


# verify pkg-config files
# man 5 pc
def unpack_pkg_config(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a pkg-config file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    isopened = False

    # lists of known property keywords from # the pkg-config specification
    # split into mandatory keywords and optional keywords.
    #
    # The specification actually says 'URL' is mandatory,
    # but many files leave it out so here it is labeled as optional
    mandatorykeywords = set(['Name', 'Version', 'Description'])
    optionalkeywords = ['Cflags', 'Cflags.private', 'Libs', 'Libs.private',
                        'Requires', 'Requires.private', 'Conflicts',
                        'Provides', 'URL']

    keywordsfound = set()

    # open the file in text mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
        validpc = True
        continued = False
        for line in checkfile:
            keywordfound = False
            # skip blank lines
            if line.strip() == '':
                continued = False
                continue
            # skip comments
            if line.startswith('#'):
                continue
            for k in mandatorykeywords:
                if line.startswith(k+':'):
                    keywordsfound.add(k)
                    keywordfound = True
                    break
            if keywordfound:
                if line.strip().endswith('\\'):
                    continued = True
                else:
                    continued = False
                continue
            for k in optionalkeywords:
                if line.startswith(k+':'):
                    keywordsfound.add(k)
                    keywordfound = True
                    break
            if keywordfound:
                if line.strip().endswith('\\'):
                    continued = True
                else:
                    continued = False
                continue

            # process variable definitions
            if not continued:
                if '=' not in line:
                    validpc = False
                    break
                pcres = re.match(r'[\w\d_]+=', line)
                if pcres is None:
                    validpc = False
                    break
            if line.strip().endswith('\\'):
                continued = True
            else:
                continued = False
    except:
        if isopened:
            checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'wrong encoding'}
        return {'status': False, 'error': unpackingerror}

    if isopened:
        checkfile.close()

    if not validpc:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'invalid format or unknown keyword'}
        return {'status': False, 'error': unpackingerror}

    if keywordsfound.intersection(mandatorykeywords) != mandatorykeywords:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'mandatory keyword missing'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize
    labels.append('pkg-config')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_pkg_config.extensions = ['.pc']
unpack_pkg_config.pretty = 'pc'


# iCalendar files
# https://www.ietf.org/rfc/rfc5545.txt
def unpack_ics(fileresult, scanenvironment, offset, unpackdir):
    '''Verify and label iCalendar files'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    isopened = False

    # open the file in text only mode
    try:
        checkfile = open(filename_full, 'r')
        isopened = True
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}

    checkfile.seek(0)

    # read the file: Python's text reader will fairly quickly
    # detect the binary files, so not a lot of extra data will
    # be read.
    try:
        icsbytes = checkfile.read()
    except:
        if isopened:
            checkfile.close()
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not a text file'}
        return {'status': False, 'error': unpackingerror}
    checkfile.close()

    try:
        icalendar.Calendar.from_ical(icsbytes)
    except:
        unpackingerror = {'offset': offset, 'fatal': False,
                          'reason': 'not valid ICS data'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize

    if offset == 0 and unpackedsize == filesize:
        labels.append("ics")
        labels.append('resource')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_ics.extensions = ['.ics']
unpack_ics.pretty = 'ics'


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


# verify smbpasswd files
# man 5 smbpasswd
def unpack_smbpasswd(fileresult, scanenvironment, offset, unpackdir):
    '''Verify a Samba password file'''
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0

    passwdentries = []

    # open the file
    try:
        checkfile = open(filename_full, 'r')
        for l in checkfile:
            linesplits = l.strip().split(':')
            if len(linesplits) < 6:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            # second field is uid
            try:
                uid = int(linesplits[1])
            except ValueError:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid UID in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            # third field is the LANMAN password hash, 32 hex digits, or all X
            if len(linesplits[2]) != 32:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid LANMAN hash in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            if linesplits[2] != 32 * 'X':
                try:
                    binascii.unhexlify(linesplits[2])
                except binascii.Error:
                    checkfile.close()
                    unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                      'reason': 'invalid LANMAN hash in smbpasswd file entry'}
                    return {'status': False, 'error': unpackingerror}

            # fourth field is the NT password hash, 32 hex digits
            if len(linesplits[3]) != 32:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid NT password hash in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}
            try:
                binascii.unhexlify(linesplits[3])
            except binascii.Error:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid NT password hash in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            # fifth field is accountflags, always 13 characters
            if len(linesplits[4]) != 13:
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid account flags in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            # account flags always include brackets
            if linesplits[4][0] != '[' or linesplits[4][-1] != ']':
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid account flags in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            # last changed field
            if not linesplits[5].startswith('LCT-'):
                checkfile.close()
                unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                                  'reason': 'invalid last changed field in smbpasswd file entry'}
                return {'status': False, 'error': unpackingerror}

            passwdentry = {}
            passwdentry['name'] = linesplits[0]
            passwdentry['uid'] = uid
            passwdentry['lanman'] = linesplits[2]
            passwdentry['ntpasswd'] = linesplits[3]
            passwdentry['flags'] = linesplits[4][1:-1].strip()
            passwdentry['changed'] = linesplits[5][4:]

            passwdentries.append(passwdentry)
    except:
        checkfile.close()
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'not enough data for entry'}
        return {'status': False, 'error': unpackingerror}

    checkfile.close()

    unpackedsize = filesize
    labels.append('smbpasswd')

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}

unpack_smbpasswd.extensions = ['smbpasswd']
unpack_smbpasswd.pretty = 'smbpasswd'

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
