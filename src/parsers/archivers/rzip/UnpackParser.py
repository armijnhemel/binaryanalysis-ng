
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_rzip

class RzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'RZIP')
    ]
    pretty_name = 'rzip'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_rzip(fileresult, scan_environment, offset, unpack_dir)

