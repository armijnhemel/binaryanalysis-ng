
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_vmdk

class VmdkUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'KDMV')
    ]
    pretty_name = 'vmdk'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vmdk(fileresult, scan_environment, offset, unpack_dir)

