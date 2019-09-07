
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_gzip

class GzipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1f\x8b\x08')
    ]
    pretty_name = 'gzip'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gzip(fileresult, scan_environment, offset, unpack_dir)

