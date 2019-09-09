
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_sparse_data

class AndroidSparseDataUnpackParser(UnpackParser):
    extensions = ['.new.dat']
    signatures = []
    pretty_name = 'androidsparsedata'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse_data(fileresult, scan_environment, offset, unpack_dir)

