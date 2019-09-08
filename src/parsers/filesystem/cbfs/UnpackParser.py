
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_cbfs

class CbfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'LARCHIVE')
    ]
    pretty_name = 'cbfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cbfs(fileresult, scan_environment, offset, unpack_dir)

