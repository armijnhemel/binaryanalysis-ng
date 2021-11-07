
import os
from bang.UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_tzdata

class TzdataUnpackParser(WrappedUnpackParser):
    extensions = ['tzdata']
    signatures = []
    pretty_name = 'tzdata'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_tzdata(fileresult, scan_environment, offset, unpack_dir)

