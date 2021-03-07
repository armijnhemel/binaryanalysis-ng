import os
import binascii
import datetime
import defusedxml.minidom
import PIL.Image
from PIL.ExifTags import TAGS as EXIF_TAGS
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import png

class PngUnpackParser(UnpackParser):
    extensions = ['png']
    signatures = [
        (0, b'\x89PNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'png'
    chunknames = set()

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
        metadata = {}
        pngtexts = []

        # TODO: eXif, tXMP, meTa
        for i in self.data.chunks:
            if i.type == 'eXIf':
                # eXIf is a recent extension to PNG. ImageMagick supports it but
                # there does not seem to be widespread adoption yet.
                # http://www.imagemagick.org/discourse-server/viewtopic.php?t=31277
                # http://ftp-osl.osuosl.org/pub/libpng/documents/proposals/eXIf/png-proposed-eXIf-chunk-2017-06-15.html
                # TODO: there are a few images out there with chunk eXif, which
                # was used in test implementations.
                if not (i.body.startswith(b'MM') or i.body.startswith(b'II')):
                    # this should never happen
                    pass
                else:
                    exif_object = PIL.Image.Exif()
                    exif_object.load(i.body)
            elif i.type == 'iTXt':
                # internationalized text
                # http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html
                # section 4.2.3.3
                if i.body.keyword == 'XML:com.adobe.xmp':
                    # the XMP specification (part 3) recommends
                    # using the iTXt chunk (section 1.1.5)
                    # https://wwwimages2.adobe.com/content/dam/acom/en/devnet/xmp/pdfs/XMP%20SDK%20Release%20cc-2016-08/XMPSpecificationPart3.pdf
                    try:
                        # XMP should be valid XML
                        xmpdom = defusedxml.minidom.parseString(i.body.text)
                        hasxmp = True
                        if 'xmp' not in metadata:
                            metadata['xmp'] = []
                        metadata['xmp'].append({'xmp': i.body.text})
                    except:
                        pngtexts.append({'key': i.body.keyword,
                                         'languagetag': i.body.language_tag,
                                         'translatedkey': i.body.translated_keyword,
                                         'value': i.body.text})
                else:
                    pngtexts.append({'key': i.body.keyword,
                                     'languagetag': i.body.language_tag,
                                     'translatedkey': i.body.translated_keyword,
                                     'value': i.body.text})
            elif i.type == 'tEXt':
                # tEXt contains key/value pairs with metadata about the PNG file.
                # section 11.3.4.3
                # Multiple tEXt chunks are allowed.
                pngtexts.append({'key': i.body.keyword, 'value': i.body.text})
            elif i.type == 'tIME':
               # tIMe chunk, should be only one
                pngdate = datetime.datetime(i.body.year, i.body.month,
                                            i.body.day, i.body.hour,
                                            i.body.minute, i.body.second)
                if 'time' not in metadata:
                    metadata['time'] = []
                metadata['time'].append({'time': pngdate.isoformat()})
            elif i.type == 'zTXt':
                # zTXt contains key/value pairs with metadata about the PNG file,
                # zlib compressed. (section 11.3.4.4)
                # Multiple zTXt chunks are allowed.
                if i.body.keyword == 'Raw profile type exif':
                    # before eXIf ImageMagick used the zTXt field to
                    # store EXIF data in hex form. python-pillow allows reading
                    # raw exif data using an Exif() object.
                    # https://github.com/python-pillow/Pillow/issues/4460
                    try:
                        exif_object = PIL.Image.Exif()
                        value = i.body.text_datastream.decode()
                        exifdata = bytes.fromhex("".join(value.split("\n")[3:]))
                        exif_object.load(exifdata)
                    except UnicodeError:
                        # TODO: what to do here?
                        pass
                elif i.body.keyword == 'Raw profile type icc':
                    # ImageMagick used the zTXt field to store ICC data
                    # in hex form.
                    try:
                       value = i.body.text_datastream.decode()
                       iccdata = bytes.fromhex("".join(value.split("\n")[3:]))
                    except UnicodeError:
                        # TODO: what to do here?
                        pass
                else:
                    try:
                        value = i.body.text_datastream.decode()
                        pngtexts.append({'key': i.body.keyword,
                                         'value': value})
                    except UnicodeError:
                        pngtexts.append({'key': i.body.keyword,
                                         'value': i.body.text_datastream})

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

        metadata['width'] = self.data.ihdr.width
        metadata['height'] = self.data.ihdr.height
        metadata['depth'] = self.data.ihdr.bit_depth
        metadata['text'] = pngtexts
        # TODO: xmp, exif

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
