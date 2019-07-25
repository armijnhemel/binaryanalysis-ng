
import os
from . import fmt_gif
from ParserException import ParserException

class GifParser:
    def __init__(self):
        self.unpacked_size = 0
    def parse(self, fileresult, scan_environment, offset):
        # try to parse the data
        # self.data = fmt_gif.Gif.from_file(fn)
        self.infile.seek(offset)
        self.data = fmt_gif.Gif.from_io(self.infile)
        self.unpacked_size = self.infile.tell() - offset
    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        try:
            filename_full = scan_environment.unpack_path(fileresult.filename)
            with filename_full.open('rb') as self.infile:
                self.parse(fileresult, scan_environment, offset)
                r = {
                        'status': True,
                        'length': self.unpacked_size
                    }
                self.set_metadata_and_labels(r, self.data)

                files_and_labels = self.unpack(fileresult, scan_environment, offset, unpack_dir)
                r['filesandlabels'] = files_and_labels
                return r
        except Exception as e:
            # raise ParserException(*e.args)
            unpacking_error = {
                    'offset': offset + self.unpacked_size,
                    'fatal' : False,
                    'reason' : e.args[0]
                }
            return { 'status' : False, 'error': unpacking_error }
    def unpack(self, fileresult, scan_environment, offset, unpack_dir):
        """extract any files from the input file"""
        if offset != 0 or self.unpacked_size != fileresult.filesize:
            outfile_rel = os.path.join(unpack_dir, "unpacked.gif")
            outfile_full = scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            os.sendfile(outfile.fileno(), self.infile.fileno(), offset, self.unpacked_size)
            outfile.close()
            # TODO: copy labels to outlabels and add 'unpacked'
            outlabels = ['gif', 'graphics', 'unpacked']
            return [ (outfile_rel, outlabels) ]
        else:
            return []
    def set_metadata_and_labels(self, unpack_results, metadata):
        """sets metadata and labels for the unpackresults"""
        extensions = [ x.body for x in self.data.blocks
                if x.block_type == self.data.BlockType.extension ]
        subblocks = [ x.body.entries for x in extensions
            if x.label == self.data.ExtensionLabel.comment ]
        # TODO: deal with duplicate comments
        comments = [b''.join([ y.bytes for y in x ]) for x in subblocks]
        unpack_results['metadata'] = {
                'width': self.data.logical_screen_descriptor.screen_width,
                'height': self.data.logical_screen_descriptor.screen_height,
                'comments': comments,
                # 'xmp': xmps
            }
        unpack_results['labels'] = [ 'gif', 'graphics' ]
        # TODO: animated


