
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_flv

class FlvUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'FLV')
    ]
    pretty_name = 'flv'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_flv(fileresult, scan_environment, offset, unpack_dir)

