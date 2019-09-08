
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_terminfo

class TerminfoUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1a\x01')
    ]
    pretty_name = 'terminfo'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_terminfo(fileresult, scan_environment, offset, unpack_dir)

