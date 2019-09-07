
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_sgi

class SgiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x01\xda')
    ]
    pretty_name = 'sgi'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sgi(fileresult, scan_environment, offset, unpack_dir)

