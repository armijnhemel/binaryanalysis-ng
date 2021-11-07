
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_vim_swapfile

class VimSwapfileUnpackParser(WrappedUnpackParser):
    extensions = ['.swp']
    signatures = [
    ]
    pretty_name = 'vimswapfile'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vim_swapfile(fileresult, scan_environment, offset, unpack_dir)

