from UnpackParserException import UnpackParserException

import os

class UnpackParser:
    extensions = []
    # signatures are tuples, (offset, bytestring)
    signatures = []

    def __init__(self):
        self.unpacked_size = 0
        self.unpack_results = {}
    def parse(self):
        """override this method to implement parsing the file data."""
        raise UnpackParserException("%s: undefined parse method" % self.__class__.__name__)
    def parse_from_offset(self, fileresult, scan_environment, offset):
        """Parses the data from a file pointed to by fileresult, starting from
        offset."""
        self.infile.seek(offset)
        self.parse()
        self.calculate_unpacked_size(offset)
    def calculate_unpacked_size(self, offset):
        """override this to calculate the length of the file data that is
        extracted. Needed if you call the UnpackParser to extract (carve)
        data that is contained in another file.
        """
        self.unpacked_size = self.infile.tell() - offset
    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        """Parses the file and unpacks any contents into other files. Files are
        stored in the filesandlabels field of the unpack_results dictionary.
        """
        try:
            filename_full = scan_environment.unpack_path(fileresult.filename)
            with filename_full.open('rb') as self.infile:
                self.parse_from_offset(fileresult, scan_environment, offset)
                self.unpack_results = {
                        'status': True,
                        'length': self.unpacked_size
                    }
                self.set_metadata_and_labels()
                files_and_labels = self.unpack(fileresult, scan_environment, offset, unpack_dir)
                self.unpack_results['filesandlabels'] = files_and_labels
                return self.unpack_results
        except Exception as e:
            # raise UnpackParserException(*e.args)
            unpacking_error = {
                    'offset': offset + self.unpacked_size,
                    'fatal' : False,
                    'reason' : "{}: {}".format(e.__class__.__name__,str(e))
                }
            return { 'status' : False, 'error': unpacking_error }
    def set_metadata_and_labels(self):
        """Override this method to set metadata and labels."""
        self.unpack_results['labels'] = []
        self.unpack_results['metadata'] = {}
    def unpack(self, fileresult, scan_environment, offset, rel_unpack_dir):
        """Override this method to unpack any data into subfiles.
        The filenames are relative to the unpack directory root that the
        scan_environment points to (usually this is a file under unpack_dir).
        Must return a list of tuples containing filename and labels.
        In this list, filename can be a Path object or a string.
        (TODO: decide which one to use.)
        """
        return []
    @classmethod
    def is_valid_extension(cls, ext):
        return ext in cls.extensions
    def extract_to_file(self, scan_environment, filename, start, length):
        """filename: path relative to unpack root"""
        outfile_full = scan_environment.unpack_path(filename)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), self.infile.fileno(), start, length)
        outfile.close()


