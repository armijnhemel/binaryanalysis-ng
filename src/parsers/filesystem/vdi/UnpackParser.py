
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_vdi

class VdiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'<<< Oracle VM VirtualBox Disk Image >>>\n')
    ]
    pretty_name = 'vdi'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vdi(fileresult, scan_environment, offset, unpack_dir)

