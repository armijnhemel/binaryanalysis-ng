
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_png

class PngUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x89PNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'png'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_png(fileresult, scan_environment, offset, unpack_dir)

