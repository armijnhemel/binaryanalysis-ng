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
import json
import time
import datetime

# import own code
import bangsignatures

## import the Python requests module to connect to Software Heritage
## https://pypi.io/project/requests
import requests

# import python bindings for Yara
import yara


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

    # open the file in binary mode
    checkfile = open(filename, 'rb')
    checkfile.close()

    return returnres


# The API of Software Heritage:
# https://archive.softwareheritage.org/api/1/
def querySoftwareHeritageChecksum(filename, hashresults, dbconn, dbcursor, scanenvironment):
    '''Contact the Software Heritage database and see if the hash is from
       a known source.
       Context: whole
       Configuration: softwareheritage
    '''

    # set the User Agent to be nice for Software Heritage, so Software Heritage
    # can identify misbehaving clients.
    useragentstring = "BANG/0.1 +https://github.com/armijnhemel/binaryanalysis-ng"
    headers = {'user-agent': useragentstring}

    # the endpoint for the Software Heritage queries. Hardcoded for now
    # but should be made configurable.
    shendpointindex = 'https://archive.softwareheritage.org/api/1/'

    checksum = hashresults['sha256']
    shresult = {}

    # continuously keep trying to query Software Heritage,
    # for a maximum of X tries, hardcoded to 5 if Software
    # Heritage does not respond.
    tries = 0

    if 'maxtries' in scanenvironment:
        maxtries = scanenvironment['maxtries']
    else:
        maxtries = 5

    ratelimitbackoff = 5
    while True:
        r = requests.get('%s/content/%s' % (shendpointindex, checksum), headers=headers)

        if r.status_code != 200:
            if r.status_code == 404:
                shresult['httpcode'] = 404
                shresult['found'] = False
                return shresult
            # first check the headers to see if it is OK to do more requests
            if r.status_code == 429:
                if 'X-RateLimit-Remaining' in r.headers:
                    ratelimit = int(r.headers['X-Ratelimit-Remaining'])
                    if ratelimit == 0:
                        if 'X-RateLimit-Reset' in r.headers:
                            rightnow = int(datetime.datetime.utcnow().timestamp())
                            try:
                                sleepuntil = int(r.headers['X-RateLimit-Reset'])
                            except:
                                pass
                            if 'Retry-After' in r.headers:
                                try:
                                    retryafter = int(r.headers['Retry-After'])
                                    print("sleeping for %d" % min(retryafter, max(0, sleepuntil - rightnow)))
                                    time.sleep(min(retryafter, max(0, sleepuntil - rightnow)))
                                except:
                                    pass
                            else:
                                print("sleeping for %d" % max(0, sleepuntil - rightnow))
                                time.sleep(max(0, sleepuntil - rightnow))
                        else:
                            # no more requests are allowed, so sleep for some time, max 60 seconds
                            # use a (somewhat) exponential backoff in case too many requests have been made
                            print("sleeping for %d" % ratelimitbackoff, filename, ratelimit, r.headers)
                            time.sleep(ratelimitbackoff)
                            if ratelimitbackoff < 60:
                                ratelimitbackoff = min(60, ratelimitbackoff * 2)
                            else:
                                ratelimitbackoff = 5
        else:
            # now process the response. This should be JSON, so decode it, and also write
            # the JSON data to a separate file for offline processing (if necessary).
            try:
                responsejson = r.json()
                print(responsejson)
            except:
                # response doesn't contain JSON, so something is wrong.
                break

            # now process the JSON content
            break
        if tries > maxtries:
            break
        tries += 1


# run Yara rules
# Get rules here: https://github.com/Yara-Rules/rules
# and make sure they have been compiled first.
def scanYara(fileinfo, dbconn, dbcursor, scanenvironment):
    '''Scan files with Yara.
       Context: whole
    '''

    # results is (for now) a list
    results = []

    try:
        rules = yara.load('/home/armijn/yara/compiled_rules')
    except Exception as e:
        print(e)
        return results

    return results
    for r in rules:
        pass
        #print(r.meta)
    try:
        yararesults = rules.match(str(filename))
        for res in yararesults:
            print(res.meta)
    except Exception as e:
        print(e)
        return results
