
import os
from UnpackParser import UnpackParser
from bangtext import unpack_passwd

class PasswdUnpackParser(UnpackParser):
    extensions = ['passwd']
    signatures = [
    ]
    pretty_name = 'passwd'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_passwd(fileresult, scan_environment, offset, unpack_dir)

