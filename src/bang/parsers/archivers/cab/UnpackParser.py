
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_cab

class CabUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'MSCF\x00\x00\x00\x00')
    ]
    pretty_name = 'cab'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cab(fileresult, scan_environment, offset, unpack_dir)

