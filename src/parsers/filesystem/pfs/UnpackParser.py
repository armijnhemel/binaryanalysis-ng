
import os
from UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_pfs

class PfsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'PFS/0.9\x00')
    ]
    pretty_name = 'pfs'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pfs(fileresult, scan_environment, offset, unpack_dir)

