
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_flv

class FlvUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FLV')
    ]
    pretty_name = 'flv'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_flv(fileresult, scan_environment, offset, unpack_dir)

