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
""" % ( self.scantree[fn]['md5'], self.scantree[fn]['sha256'] )

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
            if 'md5' in self.scantree[fn]:
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


