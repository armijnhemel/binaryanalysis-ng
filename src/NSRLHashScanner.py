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

from BaseScanner import *

class NSRLHashScanner(BaseScanner):
    '''Search a hash of a file in the NSRL database'''

    context = ['file']
    ignore = []
    needsdatabase = True


    def scan(self, fileresult):
        # results is (for now) a list
        results = []

        if self.dbconn is None:
            return results

        hash = fileresult.get_hashresult()
        # first grab a *possible* filename from the NSRL database using
        # the SHA1 of the file. At the moment just one *possible* filename
        # is recorded in the database.
        self.dbcursor.execute("SELECT filename FROM nsrl_hash WHERE sha1=%s", (hash,))
        filenameres = self.dbcursor.fetchall()
        self.dbconn.commit()

        if len(filenameres) == 0:
            return results

        manufacturercache = {}

        # get more results
        self.dbcursor.execute("SELECT n.productname, n.productversion, n.applicationtype, n.manufacturercode FROM nsrl_product n, nsrl_entry m WHERE n.productcode = m.productcode AND m.sha1=%s;", (hash,))
        productres = self.dbcursor.fetchall()
        self.dbconn.commit()
        for p in productres:
            # first create a result object
            dbres = {}
            (productname, productversion, applicationtype, manufacturercode) = p
            if manufacturercode in manufacturercache:
                manufacturer = manufacturercache[manufacturercode]
            else:
                self.dbcursor.execute("SELECT manufacturername FROM nsrl_manufacturer WHERE manufacturercode=%s", (manufacturercode,))
                manufacturerres = self.dbcursor.fetchone()
                if manufacturerres is None:
                    # this shouldn't happen
                    self.dbconn.commit()
                    return results
                manufacturer = manufacturerres[0]
                manufacturercache[manufacturercode] = manufacturer
                self.dbconn.commit()
            dbres['productname'] = productname
            dbres['productversion'] = productversion
            dbres['applicationtype'] = applicationtype
            dbres['manufacturer'] = manufacturer
            # add the result to the final list of results
            results.append(dbres)

        return results


