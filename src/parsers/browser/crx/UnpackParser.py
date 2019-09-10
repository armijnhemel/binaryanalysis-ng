
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_crx

class CrxUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'Cr24')
    ]
    pretty_name = 'crx'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_crx(fileresult, scan_environment, offset, unpack_dir)

