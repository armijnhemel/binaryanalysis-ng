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
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only


import math
import os
import sqlite3
import tempfile

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class SqliteUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'SQLite format 3\x00')
    ]
    pretty_name = 'sqlite3'

    def parse(self):
        # open the file and skip the magic
        self.infile.seek(16)

        # page size "Must be a power of two between 512 and 32768 inclusive,
        # or the value 1 representing a page size of 65536."
        checkbytes = self.infile.read(2)
        check_condition(len(checkbytes) == 2, "not enough data for pagesize")
        pagesize = int.from_bytes(checkbytes, byteorder='big')
        if pagesize == 1:
            pagesize = 65536
        else:
            check_condition(pagesize >= 512 and pagesize <= 32768,
                            "invalid page size")
            check_condition(pow(2, int(math.log2(pagesize))) == pagesize,
                            "invalid page size")

        # file format write version, 1 or 2
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for format write version")
        check_condition(ord(checkbytes) in [1,2], "invalid format write version")

        # file format read version, 1 or 2
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for format read version")
        check_condition(ord(checkbytes) in [1,2], "invalid format read version")

        # bytes for unused reserved space, usually 0, skip for now
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for reserved space")
        reservedspacebytes = ord(checkbytes)

        # maximum embedded payload fraction. "Must be 64."
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for maximum embedded payload fraction")
        check_condition(ord(checkbytes) == 64, "invalid maximum embedded payload fraction")

        # minimum embedded payload fraction. "Must be 32."
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for minimum embedded payload fraction")
        check_condition(ord(checkbytes) == 32, "invalid minimum embedded payload fraction")

        # leaf payload fraction. "Must be 32."
        checkbytes = self.infile.read(1)
        check_condition(len(checkbytes) == 1, "not enough data for leaf payload fraction")
        check_condition(ord(checkbytes) == 32, "invalid leaf payload fraction")

        # file change counter
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for file change counter")
        filechangecounter = int.from_bytes(checkbytes, byteorder='big')

        # size of database in pages
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for size of database in pages")
        dbsizeinpages = int.from_bytes(checkbytes, byteorder='big')

        check_condition(self.infile.offset + dbsizeinpages * pagesize <= self.fileresult.filesize,
                        "not enough data for database")

        # page number of the first freelist trunk page
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for first freelist trunk page")
        firstfreelistpage = int.from_bytes(checkbytes, byteorder='big')

        # total number of freelist pages
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for freelist pages number")
        num_freelist_pages = int.from_bytes(checkbytes, byteorder='big')

        # schema cookie
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for schema cookie")
        schemacookie = int.from_bytes(checkbytes, byteorder='big')

        # schema format. "Supported schema formats are 1, 2, 3, and 4."
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for schema format")
        schemaformat = int.from_bytes(checkbytes, byteorder='big')
        check_condition(schemaformat in [1, 2, 3, 4], "unsupported schema format")

        # default page cache size
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for default page cache size")
        defaultpagecachesize = int.from_bytes(checkbytes, byteorder='big')

        # largest b-tree page
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for largest b-tree page")
        largestbtreepage = int.from_bytes(checkbytes, byteorder='big')

        # database text encoding
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for database text encoding")
        textencoding = int.from_bytes(checkbytes, byteorder='big')
        check_condition(textencoding in [1, 2, 3], "unsupported text encoding")

        # user version
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for user version")
        userversion = int.from_bytes(checkbytes, byteorder='big')

        # incremental vacuum mode
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for incremental vacuum mode")
        incrementalvacuummode = int.from_bytes(checkbytes, byteorder='big')

        # application id
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for application id")

        # padding, "must be zero"
        checkbytes = self.infile.read(20)
        check_condition(checkbytes == b'\x00' * 20, "invalid padding bytes")

        # version valid for number
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for version valid for number")
        versionvalidfornumber = int.from_bytes(checkbytes, byteorder='big')

        # version of SQLite that last modified the file
        checkbytes = self.infile.read(4)
        check_condition(len(checkbytes) == 4, "not enough data for SQLite version number")
        sqliteversionnumber = int.from_bytes(checkbytes, byteorder='big')

        # The header of the file is valid. That doesn't mean that the file
        # itself is valid. On various Android systems there are SQLite files
        # that work, but where lots of fields in the header do not make sense
        # such as the number of pages. These are a bit more difficult to
        # detect.
        check_condition(dbsizeinpages != 0, "no pages in database (Android device?)")

        self.unpacked_size = dbsizeinpages * pagesize
        self.sqlitetables = []

        # extra sanity checks: see if the database can be
        # opened with Python's built-in sqlite3 module, but
        # only if the whole file is SQLite.
        if self.offset == 0 and self.unpacked_size == self.fileresult.filesize:
            dbopen = False
            try:
                testconn = sqlite3.connect('file:%s?mode=ro' % self.infile.name, uri=True)
                testcursor = testconn.cursor()
                dbopen = True
                testcursor.execute('select name, tbl_name, sql from sqlite_master;')
                tablenames = testcursor.fetchall()
                for t in tablenames:
                    sqlitetable = {}
                    sqlitetable['name'] = t[0]
                    sqlitetable['tbl_name'] = t[1]
                    sqlitetable['sql'] = t[2]
                    self.sqlitetables.append(sqlitetable)
            except Exception as e:
                raise UnpackParserException(e.args)
            finally:
                if dbopen:
                    testcursor.close()
                    testconn.close()
        else:
            temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
            os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.unpacked_size)
            os.fdopen(temporary_file[0]).close()

            dbopen = False
            try:
                testconn = sqlite3.connect('file:%s?mode=ro' % temporary_file[1], uri=True)
                testcursor = testconn.cursor()
                dbopen = True
                testcursor.execute('select name, tbl_name, sql from sqlite_master;')
                tablenames = testcursor.fetchall()
                for t in tablenames:
                    sqlitetable = {}
                    sqlitetable['name'] = t[0]
                    sqlitetable['tbl_name'] = t[1]
                    sqlitetable['sql'] = t[2]
                    self.sqlitetables.append(sqlitetable)
            except Exception as e:
                raise UnpackParserException(e.args)
            finally:
                if dbopen:
                    testcursor.close()
                    testconn.close()
                os.unlink(temporary_file[1])

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['sqlite3', 'database']
        metadata = {}
        metadata['tables'] = self.sqlitetables

        self.unpack_results.set_labels(labels)
        self.unpack_results.set_metadata(metadata)
