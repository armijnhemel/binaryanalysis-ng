
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_fstab

class FstabUnpackParser(WrappedUnpackParser):
    extensions = ['fstab']
    signatures = [
    ]
    pretty_name = 'fstab'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_fstab(fileresult, scan_environment, offset, unpack_dir)

