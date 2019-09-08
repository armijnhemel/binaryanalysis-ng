
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_romfs_ambarella

class RomfsAmbarellaUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (4, b'\x8a\x32\xfc\x66')
    ]
    pretty_name = 'romfs_ambarella'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_romfs_ambarella(fileresult, scan_environment, offset, unpack_dir)

