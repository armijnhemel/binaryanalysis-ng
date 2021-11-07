
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_chm

class ChmUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'ITSF\x03\x00\x00\x00')
    ]
    pretty_name = 'chm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_chm(fileresult, scan_environment, offset, unpack_dir)

