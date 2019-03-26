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
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import collections

class HumanReadableReporter:
    def __init__(self, reportfile):
        self.reportfile = reportfile
    def _header(self):
        scandate = self.scanresult['session']['start']
        scandatefinished = self.scanresult['session']['stop']
        checkfile = self.scanresult['session']['checkfile']
        return """SCAN RESULTS FOR: %s"
Start: %s
Stop: %s
Duration (seconds): %s

""" % ( checkfile, scandate.isoformat(), scandatefinished.isoformat(), (scandatefinished - scandate).total_seconds() )
    def _fileheader(self, fn):
        return """File: %s
%s

""" % (fn, "=" * (6 + len(fn)))
    def _filechecksum(self,fn):
        return """MD5: %s
SHA256: %s
""" % ( self.scantree[fn]['hash']['md5'], self.scantree[fn]['hash']['sha256'] )

    def _filesize(self,fn):
        return "Size: %d\n" % self.scantree[fn]['filesize']

    def _filemimetype(self,fn):
        return "MIME type: " + self.scantree[fn]['mimetype'] + "\n"
    def _fileparent(self,fn):
        return "Parent: " + self.scantree[fn]['parent'] + "\n"
    def _filelabels(self,fn):
        return "Labels: "  +  ", ".join(sorted(self.scantree[fn]['labels'])) + "\n"

    def _fileunpackedfiles(self,fn):
        bytesscanned = 0
        s = ""
        for l in self.scantree[fn]['unpackedfiles']:
            bytesscanned += l['size']
            if len(l['files']) != 0:
                s += "Data unpacked at offset %d from %s:\n%s\n" % (
                        l['offset'], l['type'], " ".join(sorted(l['files']))
                    )
        return "Bytes identified: %d (%f %%)\n" % (bytesscanned, bytesscanned/self.scantree[fn]['filesize'] * 100) + s + "\n"

    def _filetotallabels(self,fn, labels):
        s = """Total labels:
=============
"""
        for l in labels.most_common():
            s += """Name: %s
Amount: %d
""" % l
        return s

    def report(self,scanresult):

        self.scanresult = scanresult
        labelcounter = collections.Counter()
        s = self._header()
        self.scantree = scanresult['scantree']
        filenames = sorted(self.scantree.keys())
        for fn in filenames:
            s += self._fileheader(fn)
            if 'hash' in self.scantree[fn]:
                if 'md5' in self.scantree[fn]['hash']:
                    s += self._filechecksum(fn)
            if 'filesize' in self.scantree[fn]:
                s += self._filesize(fn)
            if 'mimetype' in self.scantree[fn]:
                s += self._filemimetype(fn)
            if 'parent' in self.scantree[fn]:
                s += self._fileparent(fn)
            labelcounter.update(self.scantree[fn]['labels'])
            s += self._filelabels(fn)
            bytesscanned = 0
            if 'unpackedfiles' in self.scantree[fn]:
                s += self._fileunpackedfiles(fn)
        s += self._filetotallabels(fn,labelcounter)
        s += "\n"
        self.reportfile.write(s)


