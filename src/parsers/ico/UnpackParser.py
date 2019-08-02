import os
from . import ico
from UnpackParser import UnpackParser

class IcoUnpackParser(UnpackParser):
    pretty_name = 'ico'
    extensions = [ 'ico' ]
    signatures = [
        (0, b'\x00\x00\x01\x00')
    ]
    def parse(self):
        self.data = ico.Ico.from_io(self.infile)
    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        for i in self.data.images:
            self.unpacked_size = max(self.unpacked_size, i.ofs_img + i.len_img)

    def unpack(self, fileresult, scan_environment, offset, unpack_dir):
        """extract any files from the input file"""
        if offset != 0 or self.unpacked_size != fileresult.filesize:
            outfile_rel = os.path.join(unpack_dir, "unpacked.ico")
            outfile_full = scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), self.infile.fileno(), offset, self.unpacked_size)
            outfile.close()
            outlabels = self.unpack_results['labels'] + ['unpacked']
            return [ (outfile_rel, outlabels) ]
        else:
            return []
    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        self.unpack_results['labels'] = ['graphics','ico','resource']
        self.unpack_results['metadata'] = {}

