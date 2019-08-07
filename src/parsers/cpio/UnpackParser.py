
import os
from . import cpio_new_ascii
from UnpackParser import UnpackParser

class CpioUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'cpio'

    def parse(self):
        self.data = cpio_new_ascii.CpioNewAscii.from_io(self.infile)
    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        # the cpio specs (https://www.mankier.com/5/cpio) are unclear about
        # the padding at the end of the file. It looks like the file is padded
        # to make the total file size a multiple of 16, but more research is
        # needed. For now, we ignore the padding and accept a wrong size.
    def unpack(self, fileresult, scan_environment, offset, unpack_dir):
        files_and_labels = []
        pos = 0
        for e in self.data.entries:
            if e.filename != "TRAILER!!!":
                filedata_start = e.header.hsize + e.header.nsize + e.header.npaddingsize
                # TODO: validate filename
                outfile_rel = os.path.join(unpack_dir, e.filename)
                outfile_full = scan_environment.unpack_path(outfile_rel)
                os.makedirs(outfile_full.parent, exist_ok=True)
                outfile = open(outfile_full, 'wb')
                os.sendfile(outfile.fileno(), self.infile.fileno(), pos +
                        filedata_start, e.header.fsize)
                outfile.close()
                outlabels = ['unpacked']
                files_and_labels.append( (outfile_rel, outlabels) )
            pos += e.header.bsize
        return files_and_labels
    def set_metadata_and_labels(self):
        return


