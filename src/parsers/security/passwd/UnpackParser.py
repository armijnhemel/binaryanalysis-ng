
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_passwd

class PasswdUnpackParser(WrappedUnpackParser):
    extensions = ['passwd']
    signatures = [
    ]
    pretty_name = 'passwd'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_passwd(fileresult, scan_environment, offset, unpack_dir)

