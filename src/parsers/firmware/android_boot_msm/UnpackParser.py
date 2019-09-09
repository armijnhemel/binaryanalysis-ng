
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_boot_msm

class AndroidBootMsmUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'BOOTLDR!')
    ]
    pretty_name = 'androidbootmsm'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_msm(fileresult, scan_environment, offset, unpack_dir)

