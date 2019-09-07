
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_swf

class SwfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FWS'),
        (0, b'CWS'),
        (0, b'ZWS')
    ]
    pretty_name = 'swf'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_swf(fileresult, scan_environment, offset, unpack_dir)

