
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_sgi

class SgiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01\xda')
    ]
    pretty_name = 'sgi'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sgi(fileresult, scan_environment, offset, unpack_dir)

