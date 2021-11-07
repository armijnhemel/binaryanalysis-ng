
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_wim

class WimUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'MSWIM\x00\x00\x00')
    ]
    pretty_name = 'mswim'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_wim(fileresult, scan_environment, offset, unpack_dir)

