import uuid
import pickle
import pathlib
import logging
from contextlib import contextmanager

# Rule for caching properties: only properties that are volatile (i.e. during parsing)
# or constant (such as file name) can be cached.

class MetaDirectory:
    REL_UNPACK_DIR = 'rel'
    ABS_UNPACK_DIR = 'abs'
    ROOT_PATH = 'root'

    def __init__(self, meta_root, name, is_root):
        '''Create a MetaDirectory in to meta_root. If name is
        set, it will use that name. Otherwise, if is_root is True, the name
        ROOT_PATH will be used, if False, a new name (UUID) will be created.
        '''
        self._meta_root = meta_root
        if name:
            fn = name
        elif is_root:
            fn = self.ROOT_PATH
        else:
            fn = uuid.uuid4().hex
        self._md_path = pathlib.Path(fn)
        self._file_path = None
        self._size = None
        self._unpack_parser = None

    @classmethod
    def from_md_path(cls, meta_root, name):
        '''Create an MetaDirectory from the path meta_root / name. This is useful
        if the directory already exists.
        '''
        md = MetaDirectory(meta_root, name, False)
        # read properties from persisted data
        return md

    @property
    def md_path(self):
        '''The path of the MetaDirectory, relative to the meta_root.
        IOW, the name.
        '''
        return self._md_path

    @property
    def abs_md_path(self):
        '''The absolute path of the MetaDirectory.'''
        return self._meta_root / self._md_path

    # TODO: for non-root files, store the file_path as a relative path
    # (automatic)
    @property
    def file_path(self):
        if self._file_path is None:
            p = self.abs_md_path / 'pathname'
            with p.open('r') as f:
                self._file_path = pathlib.Path(f.read())
        return self._file_path

    # TODO: for non-root files, store the file_path as a relative path
    # (automatic)
    @file_path.setter
    def file_path(self, path):
        self._file_path = path
        # persist this
        p = self.abs_md_path / 'pathname'
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('w') as f:
            f.write(str(path))


    @property
    def abs_file_path(self):
        return self._meta_root / self.file_path

    @property
    def meta_root(self):
        return self._meta_root

    @property
    def size(self):
        '''returns the size of the file this is an unpack_directory for.'''
        if self._size is None:
            # get the size
            # TODO: as a property,
            # or if it does not have it, from the file itself
            self._size = self.abs_file_path.stat().st_size
        return self._size

    @property
    def info(self):
        '''Accesses the file information stored in the MetaDirectory.'''
        path = self.abs_md_path / 'info.pkl'
        try:
            with path.open('rb') as f:
                return pickle.load(f)
        except FileNotFoundError as e:
            return {}

    @info.setter
    def info(self, data):
        '''Set the info property to data. Note: this will overwrite everything!
        '''
        logging.debug(f'info.setter: set info = {data}')
        path = self.abs_md_path / 'info.pkl'
        path.parent.mkdir(parents=True, exist_ok=True)
        logging.debug(f'info.setter: writing to {path}')
        with path.open('wb') as f:
            pickle.dump(data, f)
            logging.debug(f'info.setter: wrote info')

    def unpacked_path(self, path_name):
        '''Create a path in the MetaDirectory for an unpacked file with name path_name.
        '''
        if path_name.is_absolute():
            unpacked_path = self.md_path / self.ABS_UNPACK_DIR / path_name.relative_to('/')
        else:
            unpacked_path = self.md_path / self.REL_UNPACK_DIR / path_name
        return unpacked_path

    def unpack_regular_file(self, path, data):
        '''Unpack a file with path path into the MetaDirectory, with contents data.
        Returns the path relative to the MetaDirectory.
        '''
        unpacked_path = self.unpacked_path(path)
        full_path = self._meta_root / unpacked_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with full_path.open('wb') as f:
            f.write(data)
        return unpacked_path

    def unpack_directory(self, path):
        '''Unpack a directory with path path into the MetaDirectory.
        Returns the path relative to the MetaDirectory.
        '''
        unpacked_path = self.unpacked_path(path)
        full_path = self._meta_root / unpacked_path
        full_path.mkdir(parents=True, exist_ok=True)
        return unpacked_path

    def add_extracted_file(self, meta_dir):
        '''Adds an MetaDirectory for an extracted file to this MetaDirectory.
        '''
        logging.debug(f'add_extracted_file: adding {meta_dir.md_path} for {meta_dir.file_path}')
        info = self.info
        info.setdefault('extracted_files', {})[meta_dir.file_path] = meta_dir.md_path
        self.info = info
        logging.debug(f'add_extracted_file: wrote info {info}')

    def extracted_filename(self, offset, size):
        '''Create a filename for an extracted file, based on offset and size.
        '''
        return self.md_path / 'extracted' / f'{offset:012x}-{size:012x}'

    @property
    def extracted_files(self):
        '''The extracted files in this MetaDirectory. It is a dictionary mapping
        extracted filenames to MetaDirectory names.
        '''
        return self.info.get('extracted_files', {})
        #info = self.info
        #full_path = self._meta_root / self.md_path / 'extracted' 
        #for extracted_path in full_path.iterdir():
            #yield extracted_path

    @property
    def unpack_parser(self):
        '''The UnpackParser that should write information to this MetaDirectory
        during parsing.
        '''
        return self._unpack_parser

    @unpack_parser.setter
    def unpack_parser(self, unpack_parser):
        self._unpack_parser = unpack_parser

    def is_scanned(self):
        '''True when an UnpackParser is assigned to this MetaDirectory.
        '''
        return self._unpack_parser is not None

    def unpack_files(self):
        # TODO: should this stay or go?
        if self._unpack_parser is None:
            raise AttributeError('no unpack_parser available')
        for fn in self._unpack_parser.unpack(self):
            md = MetaDirectory(self.meta_root, None, False)
            md.file_path = fn
            yield md

