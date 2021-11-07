
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_iso9660

class Iso9660UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (32769, b'CD001')
    ]
    pretty_name = 'iso9660'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_iso9660(fileresult, scan_environment, offset, unpack_dir)

