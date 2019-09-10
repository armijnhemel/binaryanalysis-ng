
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_pnm

class PnmUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'P6'),
        (0, b'P5'),
        (0, b'P4')
    ]
    pretty_name = 'pnm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pnm(fileresult, scan_environment, offset, unpack_dir)

