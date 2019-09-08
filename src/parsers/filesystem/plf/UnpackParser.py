
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_plf

class PlfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PLF!')
    ]
    pretty_name = 'plf'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_plf(fileresult, scan_environment, offset, unpack_dir)

