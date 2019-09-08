
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_rpm

class RpmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xed\xab\xee\xdb')
    ]
    pretty_name = 'rpm'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_rpm(fileresult, scan_environment, offset, unpack_dir)

