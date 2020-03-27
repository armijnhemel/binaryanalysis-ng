
import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from . import gimp_brush

import PIL.Image

'''
class GimpBrushUnpackParserOld(WrappedUnpackParser):
    extensions = []
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gimp_brush(fileresult, scan_environment, offset, unpack_dir)
'''

class GimpBrushUnpackParser(UnpackParser):
    extensions = ['.gbr']
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def calculate_unpacked_size(self):
        try:
            self.unpacked_size = self.data.header_size + self.data.body_size
        except Exception as e:
            raise UnpackParserException(e.args)

    def parse(self):
        try:
            self.data = gimp_brush.GimpBrush.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.width > 0, "Invalid width")
        check_condition(self.data.height > 0, "Invalid height")
        check_condition(self.data.color_depth > 0, "Invalid color depth")
        check_condition(self.data.header_size > 0, "Invalid header_size")

        unpacked_size = self.data.header_size + self.data.body_size
        check_condition(unpacked_size <= self.fileresult.filesize, "Not enough data")
        try:
            self.infile.seek(self.offset)
            testimg = PIL.Image.open(self.infile)
            testimg.load()
        except Exception as e:
            raise UnpackParserException(e.args)

    def set_metadata_and_labels(self):
        self.unpack_results['labels'] = ['gimp brush', 'graphics']
        self.unpack_results['metadata'] = {'width': self.data.width,
                                           'height': self.data.height,
                                           'color_depth': self.data.color_depth}

