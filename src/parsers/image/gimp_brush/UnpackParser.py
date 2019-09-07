
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_gimp_brush

class GimpBrushUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gimp_brush(fileresult, scan_environment, offset, unpack_dir)

