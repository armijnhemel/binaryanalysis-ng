
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_swf

class SwfUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'FWS'),
        (0, b'CWS'),
        (0, b'ZWS')
    ]
    pretty_name = 'swf'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_swf(fileresult, scan_environment, offset, unpack_dir)

