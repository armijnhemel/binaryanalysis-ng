
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_minidump

class MinidumpUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MDMP')
    ]
    pretty_name = 'minidump'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_minidump(fileresult, scan_environment, offset, unpack_dir)

