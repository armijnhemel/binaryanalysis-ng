import pathlib

class FileResult:
    """stores all the information about the file that has been discovered
    so far."""
    def __init__(self, unpackdir, abs_filepath, rel_filename, abs_parentpath, rel_parentfilename, labels):
        # TODO: decide what types the paths should have: PosixPath or string
        self.unpackdir = unpackdir
        self.filepath = abs_filepath
        self.relpath = pathlib.Path(rel_filename)
        self.hash = {}
        self.filename = rel_filename
        self.parentpath = abs_parentpath
        self.parent = rel_parentfilename
        self.labels = labels
        self.unpackedfiles = None
        self.filesize = None
        self.mimetype = None
        self.mimetype_encoding = None

    def set_filesize(self, size):
        self.filesize = size

    def is_unpacking_root(self):
        return self.parentpath is None

    def get_hashresult(self):
        return self.hash

    def set_hashresult(self, hashtype, value):
        self.hash[hashtype] = value

    def init_unpacked_files(self):
        self.unpackedfiles = []

    def add_unpackedfile(self, report):
        self.unpackedfiles.append(report)

    def set_mimetype(self, mimeres):
        self.mimetype = mimeres[0]
        self.mimetype_encoding = mimeres[1]

    def get(self):
        """gets the fileresult as a dictionary."""
        d = {
            'fullfilename': str(self.filepath),
            'hash': self.hash,
            'labels': list(self.labels),
            'filename': self.filename,
        }
        if self.filesize is not None:
            d['filesize'] = self.filesize
        if self.unpackedfiles is not None:
            d['unpackedfiles'] = self.unpackedfiles
        if not self.is_unpacking_root():
            d['parent'] = self.parent
        if self.mimetype is not None:
            d['mimetype'] = self.mimetype
            if self.mimetype_encoding is not None:
                d['mimetype encoding'] = self.mimetype_encoding
        return d

    def get_filename(self):
        return self.filename

    def get_hash(self, algorithm='sha256'):
        return self.hash[algorithm]


