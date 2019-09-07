
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_aiff

class AiffUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FORM')
    ]
    pretty_name = 'aiff'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_aiff(fileresult, scan_environment, offset, unpack_dir)

