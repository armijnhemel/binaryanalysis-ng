
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_nb0

class Nb0UnpackParser(UnpackParser):
    extensions = ['.nb0']
    signatures = []
    pretty_name = 'nb0'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_nb0(fileresult, scan_environment, offset, unpack_dir)

