
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_terminfo

class TerminfoUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x1a\x01')
    ]
    pretty_name = 'terminfo'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_terminfo(fileresult, scan_environment, offset, unpack_dir)

