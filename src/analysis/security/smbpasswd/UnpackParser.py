
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_smbpasswd

class SmbpasswdUnpackParser(WrappedUnpackParser):
    extensions = ['smbpasswd']
    signatures = [
    ]
    pretty_name = 'smbpasswd'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_smbpasswd(fileresult, scan_environment, offset, unpack_dir)

