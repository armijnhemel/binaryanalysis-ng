
import os
from bang.UnpackParser import WrappedUnpackParser
from bangfilesystems import unpack_vdi

class VdiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'<<< Oracle VM VirtualBox Disk Image >>>\n')
    ]
    pretty_name = 'vdi'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vdi(fileresult, scan_environment, offset, unpack_dir)

