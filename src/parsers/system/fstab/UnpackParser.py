
import os
from UnpackParser import UnpackParser
from bangtext import unpack_fstab

class FstabUnpackParser(UnpackParser):
    extensions = ['fstab']
    signatures = [
    ]
    pretty_name = 'fstab'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_fstab(fileresult, scan_environment, offset, unpack_dir)

