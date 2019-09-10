
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_grub2font

class Grub2fontUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'FILE\x00\x00\x00\x04PFF2')
    ]
    pretty_name = 'grub2font'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_grub2font(fileresult, scan_environment, offset, unpack_dir)

