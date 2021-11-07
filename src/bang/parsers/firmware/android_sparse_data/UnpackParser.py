
import os
from bang.UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_sparse_data

class AndroidSparseDataUnpackParser(WrappedUnpackParser):
    extensions = ['.new.dat', 'new.dat.br']
    signatures = []
    pretty_name = 'androidsparsedata'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_sparse_data(fileresult, scan_environment, offset, unpack_dir)

