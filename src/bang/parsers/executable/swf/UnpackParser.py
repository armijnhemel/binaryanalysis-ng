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

import lzma
import zlib

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import swf


class SwfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'FWS'),
        (0, b'CWS'),
        (0, b'ZWS')
    ]
    pretty_name = 'swf'

    def parse(self):
        try:
            self.data = swf.Swf.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        self.unpacked_size = self.infile.tell()

        chunksize = 1024*1024

        # As of December 2018 the version number is 43:
        # https://web.archive.org/web/20210304163047/https://www.adobe.com/devnet/articles/flashplayer-air-feature-list.html
        # Compression is not supported in every version.
        if self.data.header.compression == swf.Swf.Compressions.zlib:
            check_condition(self.data.header.version >= 6,
                            "wrong SWF version number for zlib compression")

            decompressor = zlib.decompressobj()
            checkbytes = bytearray(chunksize)
            len_decompressed = 0
            while True:
                bytesread = self.infile.readinto(checkbytes)
                try:
                    # uncompress the data and count the length, but
                    # don't store the data.
                    unpackeddata = decompressor.decompress(checkbytes)
                    len_decompressed += len(unpackeddata)
                    self.unpacked_size += len(checkbytes) - len(decompressor.unused_data)
                    if len(decompressor.unused_data) != 0:
                        break
                except:
                    raise UnpackParserException('zlib decompression failure')

            check_condition(len_decompressed + 8 == self.data.header.len_file,
                            "length of decompressed data does not match declared length")

        elif self.data.header.compression == swf.Swf.Compressions.lzma:
            check_condition(self.data.header.version >= 13,
                            "wrong SWF version number for LZMA compression")

            # As standard LZMA decompression from Python does not
            # like this format and neither does lzmacat, so some tricks are needed
            # to be able to decompress this data.
            #
            # Also see:
            #
            # * https://bugzilla.mozilla.org/show_bug.cgi?format=default&id=754932
            # * http://dev.offerhq.co/ui/assets/js/plupload/src/moxie/build/swf2lzma/swf2lzma.py

            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4, "not enough data for LZMA compressed length")
            compressedlength = int.from_bytes(checkbytes, byteorder='little')
            check_condition(compressedlength + 12 + 5 <= self.infile.size,
                            "invalid length")

            # now read 1 byte for the LZMA properties
            checkbytes = self.infile.read(1)
            check_condition(len(checkbytes) == 1, "not enough data for LZMA properties")

            # compute the LZMA properties, according to
            # http://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
            # section 1.1
            props = ord(checkbytes)
            lzma_pb = props // (9 * 5)
            props -= lzma_pb * 9 * 5
            lzma_lp = props // 9
            lzma_lc = props - lzma_lp * 9

            # and 4 for the dictionary size
            checkbytes = self.infile.read(4)
            check_condition(len(checkbytes) == 4, "not enough data for LZMA dictionary size")
            dictionarysize = int.from_bytes(checkbytes, byteorder='little')

            # Create a LZMA decompressor with custom filter, as the data
            # is stored without LZMA headers.
            swf_filters = [{'id': lzma.FILTER_LZMA1,
                            'dict_size': dictionarysize,
                            'lc': lzma_lc,
                            'lp': lzma_lp,
                            'pb': lzma_pb}]

            self.unpacked_size = self.infile.tell()

            try:
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=swf_filters)
            except:
                raise UnpackParserException('unsupported LZMA properties')

            # read 1 MB chunks
            checkbytes = bytearray(chunksize)
            len_decompressed = 0
            while True:
                self.infile.readinto(checkbytes)
                try:
                    # uncompress the data and count the length, but
                    # don't store the data.
                    unpackeddata = decompressor.decompress(checkbytes)
                    len_decompressed += len(unpackeddata)
                    self.unpacked_size += len(checkbytes) - len(decompressor.unused_data)
                    if len(decompressor.unused_data) != 0:
                        break
                except:
                    raise UnpackParserException('lzma decompression failure')

            check_condition(len_decompressed + 8 == self.data.header.len_file,
                            "length of decompressed data does not match declared length")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    @property
    def labels(self):
        labels = ['swf', 'video']
        if self.data.header.compression == swf.Swf.Compressions.zlib:
            labels.append('zlib compressed swf')
        elif self.data.header.compression == swf.Swf.Compressions.lzma:
            labels.append('lzma compressed swf')
        return labels

    metadata = {}
