
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_pfs

class PfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PFS/0.9\x00')
    ]
    pretty_name = 'pfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pfs(fileresult, scan_environment, offset, unpack_dir)

