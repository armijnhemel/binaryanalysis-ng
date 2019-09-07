
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_xg3d

class Xg3dUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'XG3D')
    ]
    pretty_name = 'xg3d'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xg3d(fileresult, scan_environment, offset, unpack_dir)

