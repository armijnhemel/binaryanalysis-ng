
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_bzip2

class Bzip2UnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'BZh01AY&SY'),
        (1, b'BZh11AY&SY'),
        (2, b'BZh21AY&SY'),
        (3, b'BZh31AY&SY'),
        (4, b'BZh41AY&SY'),
        (5, b'BZh51AY&SY'),
        (6, b'BZh61AY&SY'),
        (7, b'BZh71AY&SY'),
        (8, b'BZh81AY&SY'),
        (9, b'BZh91AY&SY')
    ]
    pretty_name = 'bzip2'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bzip2(fileresult, scan_environment, offset, unpack_dir)

