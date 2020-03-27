
import os
from UnpackParser import WrappedUnpackParser
from banggames import unpack_doom_wad

class DoomWadUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_doom_wad(fileresult, scan_environment, offset, unpack_dir)

