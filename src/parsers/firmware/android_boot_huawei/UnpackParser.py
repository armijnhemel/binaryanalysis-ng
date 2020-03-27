
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_boot_huawei

class AndroidBootHuaweiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x3c\xd6\x1a\xce')
    ]
    pretty_name = 'androidboothuawei'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_huawei(fileresult, scan_environment, offset, unpack_dir)

