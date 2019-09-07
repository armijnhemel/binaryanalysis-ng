import os
from . import ico
from UnpackParser import UnpackParser

class IcoUnpackParser(UnpackParser):
    pretty_name = 'ico'
    extensions = [ '.ico' ]
    signatures = [
        (0, b'\x00\x00\x01\x00')
    ]
    def parse(self):
        self.data = ico.Ico.from_io(self.infile)
        if self.data.num_images <= 0:
            raise Exception("Invalid ico file: not enough images")
        for img in self.data.images:
            if img.width <= 0:
                raise Exception("Invalid ico file: zero or negative width")
            if img.height <= 0:
                raise Exception("Invalid ico file: zero or negative height")
            if img.num_colors <= 0:
                raise Exception("Invalid ico file: zero or negative num_colors")
            if img.num_planes <= 0:
                raise Exception("Invalid ico file: zero or negative num_planes")
            if img.bpp <= 0:
                raise Exception("Invalid ico file: zero or negative bpp")
            if img.ofs_img + img.len_img > self.fileresult.filesize:
                raise Exception("Invalid ico file: image outside of file")
            if img.ofs_img < 6 + self.data.num_images * 16:
                raise Exception("Invalid ico file: image inside header")
    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        for i in self.data.images:
            self.unpacked_size = max(self.unpacked_size, i.ofs_img + i.len_img)

    def unpack(self, fileresult, scan_environment, offset, rel_unpack_dir):
        """extract any files from the input file"""
        if offset != 0 or self.unpacked_size != fileresult.filesize:
            outfile_rel = rel_unpack_dir / "unpacked.ico"

            self.extract_to_file(scan_environment, outfile_rel, offset,
                    self.unpacked_size)
            outlabels = self.unpack_results['labels'] + ['unpacked']
            return [ (outfile_rel, outlabels) ]
        else:
            return []
    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        self.unpack_results['labels'] = ['graphics','ico','resource']
        self.unpack_results['metadata'] = {}

