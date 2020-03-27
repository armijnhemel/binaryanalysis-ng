
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_xg3d

class Xg3dUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'XG3D')
    ]
    pretty_name = 'xg3d'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xg3d(fileresult, scan_environment, offset, unpack_dir)

