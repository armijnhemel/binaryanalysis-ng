
import os
from UnpackParser import UnpackParser
from banggames import unpack_doom_wad

class DoomWadUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'IWAD')
    ]
    pretty_name = 'doomwad'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_doom_wad(fileresult, scan_environment, offset, unpack_dir)

