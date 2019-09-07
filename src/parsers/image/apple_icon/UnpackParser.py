
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_apple_icon

class AppleIconUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'icns')
    ]
    pretty_name = 'apple_icon'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_apple_icon(fileresult, scan_environment, offset, unpack_dir)

