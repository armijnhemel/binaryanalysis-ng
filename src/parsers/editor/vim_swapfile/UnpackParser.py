
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_vim_swapfile

class VimSwapfileUnpackParser(UnpackParser):
    extensions = ['.swp']
    signatures = [
    ]
    pretty_name = 'vimswapfile'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_vim_swapfile(fileresult, scan_environment, offset, unpack_dir)

