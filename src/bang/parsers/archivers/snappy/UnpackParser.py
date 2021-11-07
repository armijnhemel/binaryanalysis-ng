
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_snappy

class SnappyUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xff\x06\x00\x00\x73\x4e\x61\x50\x70\x59')
    ]
    pretty_name = 'snappy_framed'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_snappy(fileresult, scan_environment, offset, unpack_dir)

