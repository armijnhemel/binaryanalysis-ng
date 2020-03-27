
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_boot_img

class AndroidBootImgUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID!')
    ]
    pretty_name = 'androidbootimg'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_boot_img(fileresult, scan_environment, offset, unpack_dir)

