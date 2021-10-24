import os
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationLessThanError, ValidationGreaterThanError
from . import gimp_brush

from PIL.GbrImagePlugin import GbrImageFile


class GimpBrushUnpackParser(UnpackParser):
    extensions = ['.gbr']
    signatures = [
        (20, b'GIMP')
    ]
    pretty_name = 'gimpbrush'

    def calculate_unpacked_size(self):
        try:
            self.unpacked_size = self.data.len_header + self.data.len_body
        except BaseException as e:
            raise UnpackParserException(e.args)

    def parse(self):
        try:
            self.data = gimp_brush.GimpBrush.from_io(self.infile)
        except (Exception, ValidationNotEqualError, ValidationLessThanError, ValidationGreaterThanError) as e:
            raise UnpackParserException(e.args)

        check_condition(self.data.header.version < 3, "Invalid version")
        check_condition(self.data.header.version > 0, "Invalid version")
        check_condition(self.data.header.version == 2, "Unsupported version")
        check_condition(self.data.header.width > 0, "Invalid width")
        check_condition(self.data.header.height > 0, "Invalid height")
        check_condition(self.data.len_header > 0, "Invalid header_size")
        unpacked_size = self.data.len_header + self.data.len_body

        check_condition(unpacked_size <= self.infile.size, "Not enough data")
        try:
            self.infile.seek(0)
            testimg = GbrImageFile(self.infile)
            testimg.load()
        except BaseException as e:
            raise UnpackParserException(e.args)

    def write_info(self, meta_directory):
        meta_directory.info.setdefault('labels',[]).append(self.labels)
        meta_directory.info.setdefault('metadata',{}).update(self.metadata)

    labels = ['gimp brush', 'graphics']

    @property
    def metadata(self):
        return { 'width': self.data.header.width,
                'height': self.data.header.height,
                'color_depth': self.data.header.bytes_per_pixel.value
            }
