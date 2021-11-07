
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_cbfs

class CbfsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'LARCHIVE')
    ]
    pretty_name = 'cbfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_cbfs(fileresult, scan_environment, offset, unpack_dir)

