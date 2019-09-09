
import os
from UnpackParser import UnpackParser
from bangtext import unpack_lsm

class LsmUnpackParser(UnpackParser):
    extensions = ['.lsm']
    signatures = [
    ]
    pretty_name = 'lsm'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_lsm(fileresult, scan_environment, offset, unpack_dir)

