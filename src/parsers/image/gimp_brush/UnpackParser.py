
import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from . import gimp_brush

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

    def calculate_unpacked_size(self, offset):
        try:
            self.unpacked_size = self.data.header_size + self.data.body_size
        except Exception as e:
            raise UnpackParserException(e.args)
        check_condition(self.unpacked_size <= self.fileresult.filesize, "Not enough data")

    def parse(self):
        try:
            self.data = gimp_brush.GimpBrush.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.width > 0, "Invalid width")
        check_condition(self.data.height > 0, "Invalid height")
        check_condition(self.data.color_depth > 0, "Invalid color depth")
        check_condition(self.data.header_size > 0, "Invalid header_size")

