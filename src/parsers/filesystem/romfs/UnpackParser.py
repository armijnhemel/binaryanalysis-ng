
import os
from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_romfs

class RomfsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'-rom1fs-')
    ]
    pretty_name = 'romfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_romfs(fileresult, scan_environment, offset, unpack_dir)

