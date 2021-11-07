
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_trx

class TrxUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'HDR0')
    ]
    pretty_name = 'trx'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_trx(fileresult, scan_environment, offset, unpack_dir)

