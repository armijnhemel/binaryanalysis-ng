
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_uboot_legacy

class UbootLegacyUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x27\x05\x19\x56'),
        (0, b'\x83\x80\x00\x00')
    ]
    pretty_name = 'uboot_legacy'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_uboot_legacy(fileresult, scan_environment, offset, unpack_dir)

