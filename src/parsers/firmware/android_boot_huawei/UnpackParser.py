
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_boot_huawei

class AndroidBootHuaweiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3c\xd6\x1a\xce')
    ]
    pretty_name = 'androidboothuawei'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_huawei(fileresult, scan_environment, offset, unpack_dir)

