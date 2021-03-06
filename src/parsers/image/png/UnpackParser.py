import os
import binascii
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_png
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import png

#class PngUnpackParser(UnpackParser):
class PngUnpackParser(WrappedUnpackParser):
    extensions = ['png']
    signatures = [
        (0, b'\x89PNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'png'
    chunknames = set()

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_png(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = png.Png.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.ihdr.bit_depth in [1, 2, 4, 8, 16],
                "invalid bit depth")
        check_condition(self.data.ihdr.width > 0,
                "invalid width")
        check_condition(self.data.ihdr.height > 0,
                "invalid height")
        check_condition(self.data.ihdr.filter_method == 0,
                "invalid filter method")
        check_condition(self.data.ihdr.interlace_method in [0, 1],
                "invalid interlace method")

        for i in self.data.chunks:
            # compute CRC32
            computed_crc = binascii.crc32(i.type.encode('utf-8'))

            # hack for text chunks, where 'body' is text and not bytes
            try:
                computed_crc = binascii.crc32(i._raw_body, computed_crc)
            except:
                computed_crc = binascii.crc32(i.body, computed_crc)
            check_condition(computed_crc == int.from_bytes(i.crc, byteorder='big'),
                    "invalid CRC")
            self.chunknames.add(i.type)

        check_condition('IDAT' in self.chunknames,
                        "IDAT section missing")
        check_condition('IEND' in self.chunknames,
                        "IEND section missing")

    def unpack(self):
        """extract any files from the input file"""
        return []
    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'png', 'graphics' ]
        pngtexts = []

        # tEXt contains key/value pairs with metadata about the PNG file.
        # Multiple tEXt chunks are allowed.
        if 'tEXt' in self.chunknames:
            # section 11.3.4.3
            for i in self.data.chunks:
                if i.type == 'tEXt':
                    pngtexts.append({'key': i.body.keyword, 'value': i.body.text})

        # check if the PNG is animated.
        # https://wiki.mozilla.org/APNG_Specification
        if 'acTL' in self.chunknames and 'fcTL' in self.chunknames \
            and 'fdAT' in self.chunknames:
            labels.append('animated')
            labels.append('apng')

        # Check if the file is a stereo image
        if 'sTER' in self.chunknames:
            labels.append('stereo')

        # check if the file is possibly a "NinePatch" image
        # https://developer.android.com/reference/android/graphics/NinePatch
        for i in ['npTc', 'npLb', 'npOl']:
            if i in self.chunknames:
                labels.append('ninepatch')
                break

        # check if the file has an iDOT chunk, which is an undocumented
        # extension from Apple, not confirming to PNG specifications (it
        # is seen as a critical chunk by many decoders)
        if 'iDOT' in self.chunknames:
            labels.append('apple')

        # check if the file is perhaps made by ImageMagick, which used a few
        # private chunks:
        # http://www.imagemagick.org/discourse-server/viewtopic.php?t=31277
        # https://transloadit.com/blog/2017/07/new-imagemagick/
        imagemagick = False
        for i in ['vpAg', 'caNv', 'orNT']:
            if i in self.chunknames:
                labels.append('imagemagick')
                break

        # https://zdoom.org/wiki/PNG
        for i in ['grAb', 'alPh', 'huBs', 'ptIc', 'snAp', 'viSt', 'pcLs', 'raNd']:
            if i in self.chunknames:
                labels.append('zdoom')
                break

        # https://zdoom.org/wiki/Savegame
        # This was changed in September 2016
        for i in ['huBs', 'ptIc', 'snAp', 'viSt', 'pcLs', 'raNd']:
            if i in self.chunknames:
                labels.append('zdoom')
                labels.append('zdoom save game')
                break

        # check if the file was made using Adobe Fireworks
        for i in ['prVW', 'mkBT', 'mkBS', 'mkTS', 'mkBF']:
            if i in self.chunknames:
                labels.append('adobe fireworks')
                break

        self.unpack_results['metadata'] = {
                'width': self.data.ihdr.width,
                'height': self.data.ihdr.height,
                'depth': self.data.ihdr.bit_depth,
                'text': pngtexts
                # 'xmp': xmps
            }

        self.unpack_results['labels'] = labels
