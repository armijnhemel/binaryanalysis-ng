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
# Copyright 2018 - Armijn Hemel
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
import mimetypes
import os

# import own code
import bangsignatures


def knownfileNSRL(filename, hashresults, dbconn, dbcursor, scanenvironment):
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


# https://www.iana.org/assignments/media-types/media-types.xhtml
def guessExtension(filename, hashresults, dbconn, dbcursor, scanenvironment):
    '''Search the extension of the file in a list of known extensions.
       and return the mime type
       Context: file
    '''
    returnres = {}

    # results is a dictionary
    mimeres = mimetypes.guess_type(filename.name)[0]
    if mimeres is not None:
        returnres['key'] = 'mimetype'
        returnres['type'] = 'informational'
        returnres['value'] = mimeres[0]
    return returnres


# search files for license references.
def extractLicenseIdentifier(filename, hashresults, dbconn, dbcursor, scanenvironment):
    '''Search the presence of license identifiers in a file
       (URLs and other references)
       Context: file
       Ignore: archive, audio, audio, encrypted, filesystem, graphics, video
    '''

    # results is a dictionary
    returnres = {}
    licenseresults = {}

    seekbuf = bytearray(1000000)
    filesize = filename.stat().st_size

    # open the file in binary mode
    checkfile = open(filename, 'rb')
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
        if checkfile.tell() == filesize:
            break
        checkfile.seek(-50, os.SEEK_CUR)
    checkfile.close()

    if licenseresults != {}:
        returnres['key'] = 'license references'
        returnres['type'] = 'informational'
        returnres['value'] = licenseresults

    return returnres


# search files for references to forges
# https://en.wikipedia.org/wiki/Forge_(software)
def extractForgeIdentifiers(filename, hashresults, dbconn, dbcursor, scanenvironment):
    '''Search the presence of references to forges and other
       collaborative software development sites in a file
       (URLs and other references)
       Context: file
       Ignore: archive, audio, audio, encrypted, filesystem, graphics, video
    '''

    # results is a dictionary
    returnres = {}
    forgeresults = {}

    seekbuf = bytearray(1000000)
    filesize = filename.stat().st_size

    # open the file in binary mode
    checkfile = open(filename, 'rb')
    checkfile.seek(0)
    while True:
        bytesread = checkfile.readinto(seekbuf)
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

    if forgeresults != {}:
        returnres['key'] = 'forge references'
        returnres['type'] = 'informational'
        returnres['value'] = forgeresults

    return returnres
