
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_boot_img

class AndroidBootImgUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID!')
    ]
    pretty_name = 'androidbootimg'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_img(fileresult, scan_environment, offset, unpack_dir)

