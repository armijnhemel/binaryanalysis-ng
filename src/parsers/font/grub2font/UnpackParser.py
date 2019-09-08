
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_grub2font

class Grub2fontUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FILE\x00\x00\x00\x04PFF2')
    ]
    pretty_name = 'grub2font'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_grub2font(fileresult, scan_environment, offset, unpack_dir)

