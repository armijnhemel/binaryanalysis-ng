
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_sunraster

class SunrasterUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x59\xa6\x6a\x95')
    ]
    pretty_name = 'sunraster'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sunraster(fileresult, scan_environment, offset, unpack_dir)

