
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_webp

class WebpUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'WEBP')
    ]
    pretty_name = 'webp'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_webp(fileresult, scan_environment, offset, unpack_dir)

