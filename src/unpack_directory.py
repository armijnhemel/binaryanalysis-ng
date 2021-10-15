import uuid
import pickle
import pathlib

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
    def info(self):
        '''Accesses the file information stored in the unpack directory.'''
        path = self.abs_ud_path / 'info.pkl'
        with path.open('rb') as f:
            return pickle.load(f)

    @info.setter
    def info(self, data):
        path = self.abs_ud_path / 'info.pkl'
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('wb') as f:
            pickle.dump(data, f)

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

    def write_extra_data(self, data):
        '''If the unpackparser remains with extra data after parsing, this method
        will store that data.
        '''
        full_path = self._unpack_root / 'extra' / 'data'
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with full_path.open('wb') as f:
            f.write(data)
        return full_path

    def extract_data(self, offset, length, data):
        '''If the file is scanned for content, then this method will extract any
        data to the unpack_directory.
        '''
        # TODO: make context manager? e.g.
        # with ud.extract_data(....) as f:
        #     f.sendfile(...)
        full_path = self._unpack_root / 'extracted' / f'{offset:012x}-{length:012x}'
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with full_path.open('wb') as f:
            f.write(data)
        return full_path


