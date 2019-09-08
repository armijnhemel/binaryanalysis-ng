
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_vmdk

class VmdkUnpackParser(UnpackParser):
    extensions = []
    signatures = 
        (0, b'KDMV')
    ]
    pretty_name = 'vmdk'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vmdk(fileresult, scan_environment, offset, unpack_dir)

