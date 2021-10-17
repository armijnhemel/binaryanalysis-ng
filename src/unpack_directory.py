import uuid
import pickle
import pathlib
import logging
from contextlib import contextmanager

# Rule for caching properties: only properties that are volatile (i.e. during parsing)
# or constant (such as file name) can be cached.

class UnpackDirectory:
    REL_UNPACK_DIR = 'rel'
    ABS_UNPACK_DIR = 'abs'
    ROOT_PATH = 'root'

    def __init__(self, unpack_root, name, is_root):
        '''Create an unpack directory relative to unpack_root. If name is
        set, it will use that name. Otherwise, if is_root is True, the name
        ROOT_PATH will be used, if False, a new name (UUID) will be created.
        '''
        self._unpack_root = unpack_root
        if name:
            fn = name
        elif is_root:
            fn = self.ROOT_PATH
        else:
            fn = uuid.uuid4().hex
        self._ud_path = pathlib.Path(fn)
        self._file_path = None
        self._size = None
        self._unpack_parser = None

    @classmethod
    def from_ud_path(cls, unpack_root, name):
        '''Create an unpack directory from the path unpack_root / name. This is useful
        if the directory already exists.
        '''
        ud = UnpackDirectory(unpack_root, name, False)
        # read properties from persisted data
        return ud

    @property
    def ud_path(self):
        '''The path of the unpack directory, relative to the unpack_root.
        IOW, the name.
        '''
        return self._ud_path

    @property
    def abs_ud_path(self):
        '''The absolute path of the unpack directory.'''
        return self._unpack_root / self._ud_path

    # TODO: for non-root files, store the file_path as a relative path
    # (automatic)
    @property
    def file_path(self):
        if self._file_path is None:
            p = self.abs_ud_path / 'pathname'
            with p.open('r') as f:
                self._file_path = pathlib.Path(f.read())
        return self._file_path

    # TODO: for non-root files, store the file_path as a relative path
    # (automatic)
    @file_path.setter
    def file_path(self, path):
        self._file_path = path
        # persist this
        p = self.abs_ud_path / 'pathname'
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('w') as f:
            f.write(str(path))


    @property
    def abs_file_path(self):
        return self._unpack_root / self.file_path

    @property
    def unpack_root(self):
        return self._unpack_root

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
        '''Accesses the file information stored in the unpack directory.'''
        path = self.abs_ud_path / 'info.pkl'
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
        path = self.abs_ud_path / 'info.pkl'
        path.parent.mkdir(parents=True, exist_ok=True)
        logging.debug(f'info.setter: writing to {path}')
        with path.open('wb') as f:
            pickle.dump(data, f)
            logging.debug(f'info.setter: wrote info')

    def unpacked_path(self, path):
        '''Gives the path, relative to the unpack root, of an unpacked path
        that would normally have the path name *path*.
        '''
        if path.is_absolute():
            unpacked_path = self.ud_path / self.ABS_UNPACK_DIR / path.relative_to('/')
        else:
            unpacked_path = self.ud_path / self.REL_UNPACK_DIR / path
        return unpacked_path

    def write_file(self, path, data):
        '''Write data to the unpacked file normally pointed to by path.
        Returns the path in the unpack directory.
        '''
        unpacked_path = self.unpacked_path(path)
        full_path = self._unpack_root / unpacked_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with full_path.open('wb') as f:
            f.write(data)
        return unpacked_path

    def mkdir(self, path):
        '''Create a directory, that would normally have the path path.
        Returns the path in the unpack directory.
        '''
        unpacked_path = self.unpacked_path(path)
        full_path = self._unpack_root / unpacked_path
        full_path.mkdir(parents=True, exist_ok=True)
        return unpacked_path

    def add_extracted_file(self, unpack_directory):
        '''Adds an UnpackDirectory for an extracted file to this UnpackDirectory.
        '''
        logging.debug(f'add_extracted_file: adding {unpack_directory.ud_path} for {unpack_directory.file_path}')
        info = self.info
        info.setdefault('extracted_files', {})[unpack_directory.file_path] = unpack_directory.ud_path
        self.info = info
        logging.debug(f'add_extracted_file: wrote info {info}')

    def extracted_filename(self, offset, size):
        '''Create a filename for an extracted file, based on offset and size.
        '''
        return self.ud_path / 'extracted' / f'{offset:012x}-{size:012x}'

    @property
    def extracted_files(self):
        '''The extracted files in this UnpackDirectory. It is a dictionary mapping
        extracted filenames to UnpackDirectory names.
        '''
        return self.info.get('extracted_files', {})
        #info = self.info
        #full_path = self._unpack_root / self.ud_path / 'extracted' 
        #for extracted_path in full_path.iterdir():
            #yield extracted_path

    @property
    def unpack_parser(self):
        '''The UnpackParser that should write information to this UnpackDirectory
        during parsing.
        '''
        return self._unpack_parser

    @unpack_parser.setter
    def unpack_parser(self, unpack_parser):
        self._unpack_parser = unpack_parser

    def is_scanned(self):
        '''True when an UnpackParser is assigned to this UnpackDirectory.
        '''
        return self._unpack_parser is not None

    def unpack_files(self):
        # TODO: should this stay or go?
        if self._unpack_parser is None:
            raise AttributeError('no unpack_parser available')
        for fn in self._unpack_parser.unpack(self):
            ud = UnpackDirectory(self.unpack_root, None, False)
            ud.file_path = fn
            yield ud

