# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

'''
Parse and unpack PNG files. The specification of the PNG format can be found
at:

https://www.w3.org/TR/PNG/

Section 5 describes the structure of a PNG file
'''

import binascii
import json
import pathlib
import uuid
import zlib
from xml.parsers.expat import ExpatError

import defusedxml.minidom
import PIL.Image

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import png

# a list of known chunks
KNOWN_CHUNKS = set(['IHDR', 'IDAT', 'IEND', 'PLTE', 'bKGD', 'cHRM', 'gAMA',
                    'hIST', 'iCCP', 'pHYs', 'sBIT', 'sPLT', 'sRGB', 'tEXt',
                    'tIME', 'tRNS', 'zTXt', 'iTXt', 'gIFg', 'gIFx', 'gIFt',
                    'acTL', 'fcTL', 'fdAT', 'npTc', 'npLb', 'npOl', 'oFFs',
                    'vpAg', 'caNv', 'pCAL', 'tXMP', 'iDOT', 'prVW', 'mkBT',
                    'mkBS', 'mkTS', 'mkBF', 'orNT', 'sCAL', 'sTER', 'meTa',
                    'grAb', 'alPh', 'huBs', 'ptIc', 'snAp', 'viSt', 'pcLs',
                    'raNd', 'dSIG', 'eXIf', 'eXif', 'skMf', 'skRf', 'atCh'])


class PngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x89PNG\x0d\x0a\x1a\x0a')
    ]
    pretty_name = 'png'

    def parse(self):
        self.chunknames = set()
        try:
            self.data = png.Png.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args) from e

        check_condition(self.data.ihdr.width > 0,
                "invalid width")
        check_condition(self.data.ihdr.height > 0,
                "invalid height")
        check_condition(self.data.ihdr.filter_method == 0,
                "invalid filter method")
        check_condition(self.data.ihdr.interlace_method in [0, 1],
                "invalid interlace method")

        self.chunknames.add('IHDR')

        # The bytes in the IDAT chunks are part of a single zlib compressed
        # stream. Store the bytes and decompress as an extra sanity check.
        idata = b''
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
            if i.type == 'IDAT':
                idata += i.body
        try:
            zlib.decompress(idata)
        except zlib.error as e:
            raise UnpackParserException(e.args) from e

        check_condition('IDAT' in self.chunknames,
                        "IDAT section missing")
        check_condition('IEND' in self.chunknames,
                        "IEND section missing")

    def unpack(self, meta_directory):
        # Unpack embedded Evernote files
        if 'skRf' in self.chunknames:
            for i in self.data.chunks:
                if i.type == 'skRf':
                    # use the uri_uuid for the name of the PNG
                    # TODO: is this actually correct?
                    uri_uuid = uuid.UUID(bytes=i.body.uuid)
                    file_path = pathlib.Path(f"{uri_uuid}.png")

                    # The rest of the image is the original PNG.
                    with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                        outfile.write(i.body.data)
                        yield unpacked_md

        # Unpack files from PNG attach files
        if 'atCh' in self.chunknames:
            for i in self.data.chunks:
                if i.type == 'atCh':
                    if i.body.name == '':
                        file_path = pathlib.Path('unpacked_from_png')
                    elif i.body.name in ['.', '..', '/']:
                        file_path = pathlib.Path('unpacked_from_png')
                    else:
                        file_path = pathlib.Path(i.body.name)

                    if i.body.compression == png.Png.AtchChunk.CompressionAttachMethods.zlib:
                        try:
                            with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                                outfile.write(zlib.decompress(i.body.data))
                                yield unpacked_md
                        except:
                            pass
                    else:
                        with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                            outfile.write(i.body.data)
                            yield unpacked_md

    labels = [ 'png', 'graphics' ]

    @property
    def metadata(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}
        pngtexts = []
        exiftags = []
        xmptags = []
        timetags = []
        metatags = []
        png_type_labels = []

        # TODO: eXif, tXMP
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
                    exiftags.append(dict(exif_object))
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
                        xmpdom = defusedxml.minidom.parseString(i.body.text.text)
                        xmptags.append(i.body.text.text)
                    except ExpatError:
                        pngtexts.append({'key': i.body.keyword,
                                         'languagetag': i.body.language_tag,
                                         'translatedkey': i.body.translated_keyword,
                                         'value': i.body.text.text})
                else:
                    pngtexts.append({'key': i.body.keyword,
                                     'languagetag': i.body.language_tag,
                                     'translatedkey': i.body.translated_keyword,
                                     'value': i.body.text.text})
            elif i.type == 'meTa':
                try:
                    metatags.append(i.body.decode(encoding='utf-16'))
                except:
                    pass
            elif i.type == 'tEXt':
                # tEXt contains key/value pairs with metadata about the PNG file.
                # section 11.3.4.3
                # Multiple tEXt chunks are allowed.
                pngtexts.append({'key': i.body.keyword, 'value': i.body.text})
                # check to see if the file is a thumbnail.
                # https://specifications.freedesktop.org/thumbnail-spec/thumbnail-spec-latest.html
                if i.body.keyword.startswith('Thumb::'):
                    png_type_labels.append('thumbnail')
            elif i.type == 'tIME':
                # tIMe chunk, should be only one but store
                # as a list anyway
                pngdate = {'year': i.body.year,
                           'month': i.body.month,
                           'day': i.body.day,
                           'hour': i.body.hour,
                           'minute': i.body.minute,
                           'second': i.body.second}
                timetags.append(pngdate)
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
                        exiftags.append(dict(exif_object))
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
                elif i.body.keyword == 'Raw profile type xmp':
                    value = i.body.text_datastream.decode()
                    xmpdata = bytes.fromhex("".join(value.split("\n")[3:])).decode()
                    try:
                        # XMP should be valid XML
                        xmpdom = defusedxml.minidom.parseString(xmpdata)
                        xmptags.append(xmpdata)
                    except ExpatError:
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
            elif i.type == 'skMf':
                # Extract meta information from files made with Evernote/Skitch
                # http://web.archive.org/web/20210302212148/https://discussion.evernote.com/forums/topic/88532-how-to-extract-annotation-information-from-annotated-evernoteskitch-images/
                # test file: https://content.invisioncic.com/Mevernote/post-269465-0-70688200-1442655592.png
                # The metadata is in JSON format.
                try:
                    evernote_body = i.body.decode()
                    evernote_meta = json.loads(evernote_body)
                    if 'evernote' not in metadata:
                        metadata['evernote'] = {}
                    metadata['evernote']['meta'] = evernote_body
                    png_type_labels.append('evernote')
                except UnicodeError:
                    pass
                except json.JSONDecodeError:
                    pass
            elif i.type == 'skRf':
                # The first 16 bytes are a uuid that is referenced in the JSON
                # that can be found in the JSON of the skMf chunk in a URI
                uri_uuid = uuid.UUID(bytes=i.body.uuid)
                if 'evernote' not in metadata:
                    metadata['evernote'] = {}
                metadata['evernote']['uri_uuid'] = uri_uuid
            elif i.type == 'atCh':
                png_type_labels.append('pngattach')

        # check if the PNG is animated.
        # https://wiki.mozilla.org/APNG_Specification
        if 'acTL' in self.chunknames and 'fcTL' in self.chunknames \
            and 'fdAT' in self.chunknames:
            png_type_labels.append('apng')
            png_type_labels.append('animated')

        # Check if the file is a stereo image
        if 'sTER' in self.chunknames:
            png_type_labels.append('stereo png')

        # check if the file is possibly a "NinePatch" image
        # https://developer.android.com/reference/android/graphics/NinePatch
        for i in ['npTc', 'npLb', 'npOl']:
            if i in self.chunknames:
                png_type_labels.append('ninepatch')
                break

        # check if the file has an iDOT chunk, which is an undocumented
        # extension from Apple, not confirming to PNG specifications (it
        # is seen as a critical chunk by many decoders)
        if 'iDOT' in self.chunknames:
            png_type_labels.append('apple')

        # signed PNG
        if 'dSIG' in self.chunknames:
            png_type_labels.append('signed png')

        # check if the file is perhaps made by ImageMagick, which used a few
        # private chunks:
        # http://www.imagemagick.org/discourse-server/viewtopic.php?t=31277
        # https://transloadit.com/blog/2017/07/new-imagemagick/
        imagemagick = False
        for i in ['vpAg', 'caNv', 'orNT']:
            if i in self.chunknames:
                png_type_labels.append('imagemagick')
                break

        # https://zdoom.org/wiki/PNG
        for i in ['grAb', 'alPh', 'huBs', 'ptIc', 'snAp', 'viSt', 'pcLs', 'raNd']:
            if i in self.chunknames:
                png_type_labels.append('zdoom')
                break

        # https://zdoom.org/wiki/Savegame
        # This was changed in September 2016
        for i in ['huBs', 'ptIc', 'snAp', 'viSt', 'pcLs', 'raNd']:
            if i in self.chunknames:
                png_type_labels.append('zdoom')
                png_type_labels.append('zdoom save game')
                break

        # check if the file was made using Adobe Fireworks
        for i in ['prVW', 'mkBT', 'mkBS', 'mkTS', 'mkBF']:
            if i in self.chunknames:
                png_type_labels.append('adobe fireworks')
                break

        metadata['width'] = self.data.ihdr.width
        metadata['height'] = self.data.ihdr.height
        metadata['depth'] = self.data.ihdr.bit_depth
        metadata['color'] = self.data.ihdr.color_type.name
        metadata['text'] = pngtexts
        metadata['exif'] = exiftags
        metadata['xmp'] = xmptags
        metadata['time'] = timetags
        metadata['meta'] = metatags
        metadata['png_type'] = png_type_labels
        metadata['chunk_names'] = sorted(self.chunknames)

        unknownchunks = list(self.chunknames.difference(KNOWN_CHUNKS))
        metadata['unknownchunks'] = unknownchunks

        return metadata
