
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_apple_icon

class AppleIconUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'icns')
    ]
    pretty_name = 'apple_icon'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_apple_icon(fileresult, scan_environment, offset, unpack_dir)

