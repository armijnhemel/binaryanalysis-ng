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
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import os
import pathlib

import tlsh

from .UnpackParserException import UnpackParserException


class OffsetInputFile:
    def __init__(self, from_meta_directory, offset):
        self.infile = from_meta_directory.open_file
        self.offset = offset
        self._size = from_meta_directory.size

    def __getattr__(self, name):
        return self.infile.__getattribute__(name)

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            return self.infile.seek(offset + self.offset, whence)
        return self.infile.seek(offset, whence)

    def tell(self):
        return self.infile.tell() - self.offset

    def fileno(self):
        return self.infile.fileno()

    @property
    def size(self):
        return self._size - self.offset


class UnpackParser:
    """The UnpackParser class can parse input according to a certain format,
    and unpack any content from it if necessary.

    You can make an UnpackParser by deriving a class from UnpackParser and
    defining:

    extensions:
        a list of file extensions. These are strings with which the file
        needs to end. Default is empty.

    signatures:
        a list of tuples of the form (offset, bytestring), e.g.
        (0x54, b'\\x00AB\\x0a'). Default is empty.

    scan_if_featureless:
        a boolean that indicates that files for this UnpackParser do not
        always have an extension or a signature. Text-based formats often
        need this. Default is False.

    pretty_name:
        a name of the file type, used in the unpack directory name and in
        logs. There is no default.

    Override any methods if necessary.
    """
    extensions = []
    priority = 0

    signatures = []
    scan_if_featureless = False

    def __init__(self, from_meta_directory, offset, configuration):
        '''Creates an UnpackParser that will read from from_meta_directory's input file,
        starting at offset.'''
        self.offset = offset
        self.infile = OffsetInputFile(from_meta_directory, self.offset)
        self.configuration = configuration

    def parse(self):
        """Override this method to implement parsing the file data. If there is
        a (non-fatal) error during the parsing, you should raise an
        UnpackParserException.
        """
        raise UnpackParserException("%s: undefined parse method" % self.__class__.__name__)

    def parse_from_offset(self):
        """Parses the data from a file pointed to by fileresult, starting from
        offset. Normally you do not need to override this.
        """
        self.infile.seek(0)
        self.parse()
        self.calculate_unpacked_size()
        check_condition(self.unpacked_size > 0, 'Parser resulted in zero length file')

    def calculate_unpacked_size(self):
        """Override this to calculate the length of the file data that is
        extracted. Needed if you call the UnpackParser to extract (carve)
        data that is contained in another file or if the parse method does
        not read the entire content and you need a custom length calculation.
        You must assign the length to self.unpacked_size.
        """
        self.unpacked_size = self.infile.tell()

    @property
    def parsed_size(self):
        return self.unpacked_size

    def unpack(self, to_meta_directory):
        """Override this method to unpack any data into subfiles.
        The filenames will be stored in to_meta_directory root.
        For (non-fatal) errors, you should raise a UnpackParserException.
        """
        return []

    def write_info(self, to_meta_directory):
        '''update any file info or metadata to the MetaDirectory.
        Be aware that to_meta_directory.info may contain data already!
        '''
        self.record_parser(to_meta_directory)
        self.record_size(to_meta_directory)
        self.record_offset(to_meta_directory)
        self.add_labels(to_meta_directory)
        self.update_metadata(to_meta_directory)

    def record_parser(self, to_meta_directory):
        to_meta_directory.info['unpack_parser'] = self.pretty_name

    def record_size(self, to_meta_directory):
        to_meta_directory.info['size'] = self.parsed_size

    def record_offset(self, to_meta_directory):
        to_meta_directory.info['offset'] = self.offset

    def add_labels(self, to_meta_directory):
        to_meta_directory.info.setdefault('labels',[]).extend(set(self.labels))

    def update_metadata(self, to_meta_directory):
        to_meta_directory.info.setdefault('metadata',{}).update(self.metadata)

    @classmethod
    def is_valid_extension(cls, ext):
        return ext in cls.extensions


class ExtractedParser(UnpackParser):

    @classmethod
    def with_size(cls, from_meta_directory, offset, size, configuration):
        o = cls(from_meta_directory, offset, configuration)
        o.unpacked_size = size
        return o

    def parse_from_offset(self):
        pass

    def parse(self):
        pass

    pretty_name = 'extractedparser'
    labels = []
    metadata = {}

    def unpack(self, to_meta_directory):
        # synthesized files must be scanned again (with featureless parsers),
        # so let them unpack themselves  but first, write the info data before
        # the meta directory is queued.
        to_meta_directory.write_ahead()
        yield to_meta_directory


class SynthesizingParser(UnpackParser):

    @classmethod
    def with_size(cls, from_meta_directory, offset, size, configuration):
        o = cls(from_meta_directory, offset, configuration)
        o.unpacked_size = size
        return o

    def parse_from_offset(self):
        pass

    def parse(self):
        pass

    pretty_name = 'synthesizingparser'
    labels = ['synthesized']
    metadata = {}

    def unpack(self, to_meta_directory):
        # synthesized files must be scanned again (with featureless parsers),
        # so let them unpack themselves # but first, write the info data before
        # the meta directory is queued.
        to_meta_directory.write_ahead()
        yield to_meta_directory


class PaddingParser(UnpackParser):

    valid_padding_chars = [b'\x00', b'\xff']

    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.is_padding = False

    def parse(self):
        size = 0
        is_padding = False

        c = self.infile.read(1)
        padding_char = c
        is_padding = c in self.valid_padding_chars
        if is_padding:
            while c == padding_char:
                c = self.infile.read(1)
                size += 1
            ispadding = c == b''
        self.unpacked_size = size
        self.is_padding = is_padding

    def calculate_unpacked_size(self):
        pass

    def write_info(self, to_meta_directory):
        if self.is_padding:
            to_meta_directory.info.setdefault('labels', []).append('padding')


class ExtractingParser(UnpackParser):
    '''If a file is parsed and consists of more than one file extra data, we extract the files
    into a new MetaDirectory. If you want to record extra metadata for the parent
    MetaDirectory, assign this parser to it.
    '''
    @classmethod
    def with_parts(cls, from_meta_directory, parts, configuration):
        '''the sum of all lengths in parts is the calculated file size.'''
        o = cls(from_meta_directory, 0, configuration)
        o._parts = parts
        size = sum(p[1] for p in parts)
        o.unpacked_size = size
        return o

    def parse_from_offset(self):
        pass

    def parse(self):
        pass

    def write_info(self, to_meta_directory):
        '''TODO: write any data about the parent MetaDirectory here.'''
        pass

class StringExtractingParser(UnpackParser):
    '''Parser to extract human readable ASCII strings from binaries'''
    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory
        self.offset = offset
        self.strings = []

    pretty_name = 'stringextractingparser'

    def parse(self):
        # reset the file pointer to extract strings
        self.infile.seek(self.offset)

        # start reading data in chunks of 10 MiB
        read_size = 10485760

        # then read the data
        scanbytes = bytearray(read_size)
        bytes_read = self.file.readinto(scanbytes)

        while bytes_read != 0:
            data = memoryview(scanbytes[:bytes_read])
            # first see if there is a \x00 in the data

            # split the read data and extract the strings
            for s in data.split(b'\x00'):
                try:
                    decoded_strings = s.decode().splitlines()
                    for decoded_string in decoded_strings:
                        for rc in REMOVE_CHARACTERS:
                            if rc in decoded_string:
                                decoded_string = decoded_string.translate(REMOVE_CHARACTERS_TABLE)

                        if len(decoded_string) < string_cutoff_length:
                            continue
                        if decoded_string.isspace():
                            continue

                        translated_string = decoded_string.translate(STRING_TRANSLATION_TABLE)
                        if decoded_string.isascii():
                            # test the translated string
                            if translated_string.isprintable():
                                self.strings.append(decoded_string)
                        else:
                            self.strings.append(decoded_string)
                except UnicodeDecodeError:
                    pass

            # read more bytes
            bytes_read = self.file.readinto(scanbytes)

        if self.strings:
            self.update_metadata(self.from_md)
            self.from_md.write_ahead()

    def calculate_unpacked_size(self):
        self.unpacked_size = 0

    labels = []

    @property
    def metadata(self):
        metadata = self.from_md.info.get('metadata', {})
        metadata['strings'] = self.strings
        return metadata


class TlshParser(UnpackParser):
    def __init__(self, from_meta_directory, offset, configuration):
        super().__init__(from_meta_directory, offset, configuration)
        self.from_md = from_meta_directory
        self.offset = offset

    pretty_name = 'hashparser'

    def parse(self):
        # reset the file pointer to compute TLSH
        self.infile.seek(self.offset)
        self.hash_results = compute_tlsh(self.infile)

        if self.hash_results is not None:
            self.update_metadata(self.from_md)
            self.from_md.write_ahead()

    def calculate_unpacked_size(self):
        self.unpacked_size = 0

    labels = []

    @property
    def metadata(self):
        metadata = self.from_md.info.get('metadata', {})
        if 'hashes' not in metadata:
            metadata['hashes'] = {}
        metadata['hashes']['tlsh'] = self.hash_results
        return metadata

def compute_tlsh(open_file):
    '''Compute TLSH hash for files. By default a few hashes have
    been hardcoded. To compute different hashes change this file.
    '''

    # read data in blocks of 10 MiB
    read_size = 10485760

    # TLSH maximum size
    tlsh_maximum = 31457280

    tlsh_hash = tlsh.Tlsh()

    # then read the data
    bytes_processed = 0
    scanbytes = bytearray(read_size)
    bytes_read = open_file.readinto(scanbytes)

    while bytes_read != 0:
        bytes_processed += bytes_read
        data = memoryview(scanbytes[:bytes_read])
        tlsh_hash.update(data.tobytes())
        bytes_read = open_file.readinto(scanbytes)

    tlsh_hash.final()

    try:
        return tlsh_hash.hexdigest()
    except ValueError:
        # not enough entropy in input file
        return

def compute_hashes(open_file):
    '''Compute various hashes for files. By default a few hashes have
    been hardcoded. To compute different hashes change this file.
    '''
    hash_algorithms = ['sha256', 'md5', 'sha1']

    # read data in blocks of 10 MiB
    read_size = 10485760

    hashes = {}
    for h in hash_algorithms:
        hashes[h] = hashlib.new(h)

    # then read the data
    bytes_processed = 0
    scanbytes = bytearray(read_size)
    bytes_read = open_file.readinto(scanbytes)

    while bytes_read != 0:
        bytes_processed += bytes_read
        data = memoryview(scanbytes[:bytes_read])
        for h in hashes:
            hashes[h].update(data)
        bytes_read = open_file.readinto(scanbytes)

    hash_results = dict([(algorithm, computed_hash.hexdigest())
        for algorithm, computed_hash in hashes.items()])

    return hash_results

def check_condition(condition, message):
    '''semantic check function to see if condition is True.
    Raises an UnpackParserException with message if not.
    '''
    if not condition:
        raise UnpackParserException(message)
