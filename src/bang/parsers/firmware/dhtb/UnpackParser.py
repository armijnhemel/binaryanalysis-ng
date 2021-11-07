
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_dhtb

class DhtbUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'DHTB\x01\x00\x00')
    ]
    pretty_name = 'dhtb'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dhtb(fileresult, scan_environment, offset, unpack_dir)

