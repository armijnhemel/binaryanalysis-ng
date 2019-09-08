
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_trx

class TrxUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'HDR0')
    ]
    pretty_name = 'trx'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_trx(fileresult, scan_environment, offset, unpack_dir)

