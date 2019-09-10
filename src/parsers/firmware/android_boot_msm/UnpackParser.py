
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_boot_msm

class AndroidBootMsmUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'BOOTLDR!')
    ]
    pretty_name = 'androidbootmsm'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_msm(fileresult, scan_environment, offset, unpack_dir)

