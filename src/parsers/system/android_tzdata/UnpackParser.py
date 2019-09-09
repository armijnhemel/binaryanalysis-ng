
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_tzdata

class TzdataUnpackParser(UnpackParser):
    extensions = ['tzdata']
    signatures = []
    pretty_name = 'tzdata'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_tzdata(fileresult, scan_environment, offset, unpack_dir)

