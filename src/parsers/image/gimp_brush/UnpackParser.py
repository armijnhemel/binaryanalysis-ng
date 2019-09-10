
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_gimp_brush

class GimpBrushUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gimp_brush(fileresult, scan_environment, offset, unpack_dir)

