import os
from . import gif
from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError

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
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        except BaseException as e:
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

        metadata = { 'width': self.data.logical_screen_descriptor.screen_width,
                     'height': self.data.logical_screen_descriptor.screen_height}

        iccprofiles = []
        applications = []

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
                elif app_identifier == 'MGK8BIM0' and auth_code == b'000':
                    # extension specific to ImageMagick
                    pass
                elif app_identifier == 'MGKIPTC0' and auth_code == b'000':
                    # extension specific to ImageMagick
                    pass

        if iccprofiles != []:
            metadata['iccprofiles'] = iccprofiles

        subblocks = [ x.body.entries for x in extensions
            if x.label == self.data.ExtensionLabel.comment ]
        # TODO: deal with duplicate comments
        comments = [b''.join([ y.bytes for y in x ]) for x in subblocks]
        metadata['comments'] = comments
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels([ 'gif', 'graphics' ])
