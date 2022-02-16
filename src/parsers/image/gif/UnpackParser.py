# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import os
import defusedxml.minidom
from . import gif
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError

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
        # TODO: decide what exceptions to catch
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
            raise UnpackParserException(e.args)

    def unpack(self):
        """extract any files from the input file"""
        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        extensions = [ x.body for x in self.data.blocks
                if x.block_type == self.data.BlockType.extension ]

        labels = ['gif', 'graphics']
        metadata = { 'width': self.data.logical_screen_descriptor.screen_width,
                     'height': self.data.logical_screen_descriptor.screen_height}

        applications = []

        iccprofiles = []
        xmps = []

        # process "applications" and "comments"
        for extension in extensions:
            if extension.label == gif.Gif.ExtensionLabel.application:
                app_identifier = extension.body.application_id.application_identifier
                auth_code = extension.body.application_id.application_auth_code
                applications.append((app_identifier, auth_code))
                if app_identifier == "NETSCAPE" and auth_code == b'2.0':
                    # http://fileformats.archiveteam.org/wiki/GIF#Known_application_extensions
                    # http://giflib.sourceforge.net/whatsinagif/bits_and_bytes.html#application_extension_block
                    # The Netscape extension is for animations.
                    metadata['animated'] = True
                elif app_identifier == "ANIMEXTS" and auth_code == b'1.0':
                    metadata['animated'] = True
                elif app_identifier == "XMP Data" and auth_code == b'XMP':
                    # https://github.com/adobe/xmp-docs/blob/master/XMPSpecifications/XMPSpecificationPart3.pdf
                    xmp = b''
                    for subblock in extension.body.subblocks:
                        xmp += subblock.len_bytes.to_bytes(1, byteorder='little')
                        xmp += subblock.bytes
                    try:
                        # cut off the 258 magic footer
                        xmp = xmp[:-258]

                        # UTF-8 encoded
                        xmp = xmp.decode()

                        # and valid XML
                        xmpdom = defusedxml.minidom.parseString(xmp)
                        xmps.append(xmp)
                    except:
                        pass
                elif app_identifier == "ICCRGBG1" and auth_code == b'012':
                    # ICC profiles, http://www.color.org/icc1V42.pdf,
                    # section B.6
                    iccprofile = b''
                    for subblock in extension.body.subblocks:
                        iccprofile += subblock.bytes
                    iccprofiles.append(iccprofile)
                elif app_identifier == "ADOBE:IR" and auth_code == b'1.0':
                    # extension specific to Adobe Image Ready(?)
                    pass
                elif app_identifier == "STARDIV " and auth_code == b'5.0':
                    # extension specific to old versions of StarOffice
                    pass
                elif app_identifier == 'ImageMag' and auth_code == b'ick':
                    # extension specific to ImageMagick
                    pass
                elif app_identifier == 'ImageMag' and auth_code == b'ick':
                    # extension specific to ImageMagick
                    pass
                elif app_identifier == 'MGK8BIM0' and auth_code == b'000':
                    # extension specific to ImageMagick
                    pass
                elif app_identifier == 'MGKIPTC0' and auth_code == b'000':
                    # extension specific to ImageMagick
                    pass
                elif app_identifier == 'AUDIOGIF' and auth_code == b'0.1':
                    # https://github.com/RancidBacon/audiogif
                    pass
                elif app_identifier == 'MIDICTRL' and auth_code == b'Jon':
                    # http://www.midiox.com/txt/mmginf.txt
                    # https://exiftool.org/forum/index.php?topic=8315.0
                    pass
                elif app_identifier == 'MIDISONG' and auth_code == b'Dm7':
                    # http://www.midiox.com/txt/mmginf.txt
                    pass
                elif app_identifier == 'PCM-CTRL' and auth_code == b'dem':
                    # http://www.midiox.com/txt/mmginf.txt
                    pass
                elif app_identifier == 'PCM-FRMT' and auth_code == b'tel':
                    # http://www.midiox.com/txt/mmginf.txt
                    pass
                elif app_identifier == 'PCM-DATA' and auth_code == b'jwo':
                    # http://www.midiox.com/txt/mmginf.txt
                    pass
                elif app_identifier == 'TALKRAPP' and auth_code == b'COM':
                    # https://github.com/talkr-app/gif-talkr
                    pass

        metadata['xmp'] = xmps
        metadata['iccprofiles'] = iccprofiles

        subblocks = [ x.body.entries for x in extensions
            if x.label == self.data.ExtensionLabel.comment ]
        # TODO: deal with duplicate comments
        comments = [b''.join([ y.bytes for y in x ]) for x in subblocks]
        metadata['comments'] = comments
        metadata['applications'] = applications
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
