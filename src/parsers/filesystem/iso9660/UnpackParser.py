
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_iso9660

class Iso9660UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (32769, b'CD001')
    ]
    pretty_name = 'iso9660'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_iso9660(fileresult, scan_environment, offset, unpack_dir)

