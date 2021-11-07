
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_webp

class WebpUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (8, b'WEBP')
    ]
    pretty_name = 'webp'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_webp(fileresult, scan_environment, offset, unpack_dir)

