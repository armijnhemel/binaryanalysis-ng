
import os
from . import gif
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class GifUnpackParser(UnpackParser):
    extensions = ['.gif']
    signatures = [
        (0, b'GIF87a'),  # https://www.w3.org/Graphics/GIF/spec-gif89a.txt
        (0, b'GIF89a'),  # https://www.w3.org/Graphics/GIF/spec-gif89a.txt
    ]
    pretty_name = 'gif'

    def parse(self):
        try:
            self.data = gif.Gif.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.logical_screen_descriptor.screen_width > 0,
                "invalid width")
        check_condition(self.data.logical_screen_descriptor.screen_height > 0,
                "invalid height")
    def unpack(self):
        """extract any files from the input file"""
        return []
    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        extensions = [ x.body for x in self.data.blocks
                if x.block_type == self.data.BlockType.extension ]
        subblocks = [ x.body.entries for x in extensions
            if x.label == self.data.ExtensionLabel.comment ]
        # TODO: deal with duplicate comments
        comments = [b''.join([ y.bytes for y in x ]) for x in subblocks]
        self.unpack_results['metadata'] = {
                'width': self.data.logical_screen_descriptor.screen_width,
                'height': self.data.logical_screen_descriptor.screen_height,
                'comments': comments,
                # 'xmp': xmps
            }
        self.unpack_results['labels'] = [ 'gif', 'graphics' ]
        # TODO: animated


