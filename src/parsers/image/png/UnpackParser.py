
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_png

class PngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (8, b'\x89PNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'png'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_png(fileresult, scan_environment, offset, unpack_dir)

