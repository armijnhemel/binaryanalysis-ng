#!/usr/bin/python3

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

# This file has several methods for scanning files
# Each file has the following parameters:
#
# * filename (pathlib.Path object)
# * hashes (as a dict)
# * database connection object (PostgreSQL)
# * database cursor object (PostgreSQL)
# * scan environment (a dict)

import pathlib
import os

# import own code
import bangsignatures


def knownfileNSRL(fileresult, hashresults, dbconn, dbcursor, scanenvironment):
    '''Search a hash of a file in the NSRL database
       Context: file
    '''
    # results is (for now) a list
    results = []

    if dbconn is None:
        return results

    # first grab a *possible* filename from the NSRL database using
    # the SHA1 of the file. At the moment just one *possible* filename
    # is recorded in the database.
    dbcursor.execute("SELECT filename FROM nsrl_hash WHERE sha1=%s", (hashresults['sha1'],))
    filenameres = dbcursor.fetchall()
    dbconn.commit()

    if len(filenameres) == 0:
        return results

    manufacturercache = {}

    # get more results
    dbcursor.execute("SELECT n.productname, n.productversion, n.applicationtype, n.manufacturercode FROM nsrl_product n, nsrl_entry m WHERE n.productcode = m.productcode AND m.sha1=%s;", (hashresults['sha1'],))
    productres = dbcursor.fetchall()
    dbconn.commit()
    for p in productres:
        # first create a result object
        dbres = {}
        (productname, productversion, applicationtype, manufacturercode) = p
        if manufacturercode in manufacturercache:
            manufacturer = manufacturercache[manufacturercode]
        else:
            dbcursor.execute("SELECT manufacturername FROM nsrl_manufacturer WHERE manufacturercode=%s", (manufacturercode,))
            manufacturerres = dbcursor.fetchone()
            if manufacturerres is None:
                # this shouldn't happen
                dbconn.commit()
                return results
            manufacturer = manufacturerres[0]
            manufacturercache[manufacturercode] = manufacturer
            dbconn.commit()
        dbres['productname'] = productname
        dbres['productversion'] = productversion
        dbres['applicationtype'] = applicationtype
        dbres['manufacturer'] = manufacturer
        # add the result to the final list of results
        results.append(dbres)

    return results

knownfileNSRL.context = ['file']
knownfileNSRL.ignore = []

# search files for license and forge references.
# https://en.wikipedia.org/wiki/Forge_(software)
def extractIdentifier(fileresult, hashresults, dbconn, dbcursor, scanenvironment):
    '''Search the presence of license identifiers in a file
       (URLs and other references)
       Search the presence of references to forges and other
       collaborative software development sites in a file
       (URLs and other references)
       Context: file
       Ignore: archive, audio, audio, database, encrypted, filesystem, graphics, video
    '''

    # results is a dictionary, constructed as:
    returnres = {}
    licenseresults = {}
    forgeresults = {}

    seekbuf = bytearray(1000000)
    # filesize = filename.stat().st_size
    filename_full = scanenvironment.unpack_path(fileresult.filename)
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

extractIdentifier.context = ['file']
extractIdentifier.ignore = ['archive', 'audio', 'audio', 'database', 'encrypted', 'filesystem', 'graphics', 'video']

import inspect
import sys

bangfunctions = inspect.getmembers(sys.modules[__name__], inspect.isfunction)
bangfilefunctions = [func for name, func in bangfunctions
        if func.context == 'file']
bangwholecontextfunctions = [func for name, func in bangfunctions
        if func.context == 'whole']



