
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_romfs

class RomfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'-rom1fs-')
    ]
    pretty_name = 'romfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_romfs(fileresult, scan_environment, offset, unpack_dir)

