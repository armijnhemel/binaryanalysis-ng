
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_uboot_legacy

class UbootLegacyUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x27\x05\x19\x56')
    ]
    pretty_name = 'uboot_legacy'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_uboot_legacy(fileresult, scan_environment, offset, unpack_dir)

