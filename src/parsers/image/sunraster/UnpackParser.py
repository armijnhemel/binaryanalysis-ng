
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_sunraster

class SunrasterUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x59\xa6\x6a\x95')
    ]
    pretty_name = 'sunraster'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sunraster(fileresult, scan_environment, offset, unpack_dir)

