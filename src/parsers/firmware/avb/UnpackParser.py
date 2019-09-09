
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_avb

class AvbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'AVB0')
    ]
    pretty_name = 'avb'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_avb(fileresult, scan_environment, offset, unpack_dir)

