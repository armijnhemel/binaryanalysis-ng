
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_romfs_ambarella

class RomfsAmbarellaUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (4, b'\x8a\x32\xfc\x66')
    ]
    pretty_name = 'romfs_ambarella'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_romfs_ambarella(fileresult, scan_environment, offset, unpack_dir)

