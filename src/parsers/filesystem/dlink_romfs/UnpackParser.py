
import os
from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_dlink_romfs

class DlinkRomfsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (16, b'ROMFS v')
    ]
    pretty_name = 'dlinkromfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dlink_romfs(fileresult, scan_environment, offset, unpack_dir)

