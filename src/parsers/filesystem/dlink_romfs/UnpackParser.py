
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_dlink_romfs

class DlinkRomfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (16, b'ROMFS v')
    ]
    pretty_name = 'dlinkromfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dlink_romfs(fileresult, scan_environment, offset, unpack_dir)

