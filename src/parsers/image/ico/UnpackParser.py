import os
from . import ico
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class IcoUnpackParser(UnpackParser):
    pretty_name = 'ico'
    extensions = [ '.ico' ]
    signatures = [
        (0, b'\x00\x00\x01\x00')
    ]
    def parse(self):
        try:
                self.data = ico.Ico.from_io(self.infile)
        except Exception as e:
                raise UnpackParserException(e.args)
        check_condition(self.data.num_images > 0,
                "Invalid ico file: not enough images")
        for img in self.data.images:
            check_condition(img.width > 0,
                    "Invalid ico file: zero or negative width")
            check_condition(img.height > 0,
                    "Invalid ico file: zero or negative height")
            check_condition(img.num_colors > 0,
                    "Invalid ico file: zero or negative num_colors")
            check_condition(img.num_planes > 0,
                    "Invalid ico file: zero or negative num_planes")
            check_condition(img.bpp > 0,
                    "Invalid ico file: zero or negative bpp")
            check_condition(img.ofs_img + img.len_img <= self.fileresult.filesize,
                    "Invalid ico file: image outside of file")
            check_condition(img.ofs_img >= 6 + self.data.num_images * 16,
                    "Invalid ico file: image inside header")
    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.tell() - self.offset
        for i in self.data.images:
            self.unpacked_size = max(self.unpacked_size, i.ofs_img + i.len_img)

    def unpack(self):
        """extract any files from the input file"""
        return []
    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        self.unpack_results['labels'] = ['graphics','ico','resource']
        self.unpack_results['metadata'] = {}

