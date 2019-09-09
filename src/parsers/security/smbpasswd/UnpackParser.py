
import os
from UnpackParser import UnpackParser
from bangtext import unpack_smbpasswd

class SmbpasswdUnpackParser(UnpackParser):
    extensions = ['smbpasswd']
    signatures = [
    ]
    pretty_name = 'smbpasswd'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_smbpasswd(fileresult, scan_environment, offset, unpack_dir)

