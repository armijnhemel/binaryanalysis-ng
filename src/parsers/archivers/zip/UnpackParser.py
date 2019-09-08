
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_zip

class ZipUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x50\x4b\x03\04')
    ]
    pretty_name = 'zip'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_zip(fileresult, scan_environment, offset, unpack_dir)

