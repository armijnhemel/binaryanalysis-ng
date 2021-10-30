import uuid
import mmap
import pickle
import pathlib
import logging
from contextlib import contextmanager

# The MetaDirectory caches the info field, to avoid unnecessary disk access. This means
# that at most one MetaDirectory object should exist for a given meta directory. Aliases to
# the same MetaDirectory are not a problem, when entering the MetaDirectory.open() context,
# the info field is not re-read if it is not empty. When leaving the context, the info field
# is written to disk.


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
        self._open_file = None
        self._mapped_file = None
        self.info = {}

    @classmethod
    def from_md_path(cls, meta_root, name):
        '''Create an MetaDirectory from the path meta_root / name. This is useful
        if the directory already exists.
        '''
        md = MetaDirectory(meta_root, name, False)
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

    @property
    def file_path(self):
        '''The path of the file that this MetaDirectory refers to, relative to the MetaDirectory.'''
        if self._file_path is None:
            p = self.abs_md_path / 'pathname'
            with p.open('r') as f:
                self._file_path = pathlib.Path(f.read())
        return self._file_path

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
        '''The absolute path of the file that this MetaDirectory refers to.'''
        return self._meta_root / self.file_path

    @property
    def meta_root(self):
        '''The absolute path of the MetaDirectory.'''
        return self._meta_root

    @property
    def size(self):
        '''the size of the file that the MetaDirectory refers to.'''
        if self._size is None:
            # get the size
            # TODO: as a property,
            # or if it does not have it, from the file itself
            self._size = self.abs_file_path.stat().st_size
        return self._size

    @contextmanager
    def open(self, open_file=True):
        '''Context manager to "open" the MetaDirectory. Yields itself.
        It opens the file, mmaps the file and reads the information stored in the
        metadirectory. When exiting the context, it will save the information to the
        MetaDirectory and close the file.
        We need both the open file and the mmaped file, since sendfile wants an actual
        file object, and we also want the advantages of mmap.
        If open_file is False, or the file is already open, this context manager will not
        touch the file.
        If the info is not empty, it will not read it from the info file. During the
        processing loop multiple references to the same MetaDirectory can exist, and we
        want to be able to "open" them, even if they are already open. If we would
        re-read the information from the info file, any changes would be lost. We always
        write the information upon leaving the context. This works well as long as the
        references to the MetaDirectory are all in the same thread.
        '''
        open_file = open_file or (self._open_file is None)
        if open_file:
                self._open_file = self.abs_file_path.open('rb')
                try:
                    self._mapped_file = mmap.mmap(self._open_file.fileno(),0, access=mmap.ACCESS_READ)
                except ValueError as e:
                    logging.warning(f'[{self.md_path}]open: error mmapping {self.abs_file_path}: {e}')
        if self.info == {}:
            self.info = self._read_info()
            logging.debug(f'[{self.md_path}]open: opening context, reading info {self.info}')
        try:
            yield self
        finally:
            if open_file:
                self._open_file.close()
                self._open_file = None
                self._mapped_file = None
            logging.debug(f'[{self.md_path}]open: closing context, writing info {self.info}')
            self._write_info(self.info)

    @property
    def open_file(self):
        '''Returns a file object for the opened file that this MetaDirectory represents.
        '''
        return self._open_file

    @property
    def mapped_file(self):
        '''Returns an mmap object for the opened file that this MetaDirectory represents.
        '''
        return self._mapped_file

    def _read_info(self):
        '''Reads the file information stored in the MetaDirectory.'''
        path = self.abs_md_path / 'info.pkl'
        logging.debug(f'[{self.md_path}]_read_info: reading from {path}')
        try:
            with path.open('rb') as f:
                return pickle.load(f)
        except FileNotFoundError as e:
            return {}

    def _write_info(self, data):
        '''Set the info property to data. Note: this will overwrite everything!
        '''
        logging.debug(f'[{self.md_path}]_write_info: set info = {data}')
        path = self.abs_md_path / 'info.pkl'
        path.parent.mkdir(parents=True, exist_ok=True)
        logging.debug(f'[{self.md_path}]_write_info: writing to {path}')
        with path.open('wb') as f:
            pickle.dump(data, f)
            logging.debug(f'[{self.md_path}]_write_info: wrote info')

    @property
    def unpacked_abs_root(self):
        return self.md_path / self.ABS_UNPACK_DIR

    @property
    def unpacked_rel_root(self):
        return self.md_path / self.REL_UNPACK_DIR

    def unpacked_path(self, path_name):
        '''Gives a path in the MetaDirectory for an unpacked file with name path_name.
        '''
        if path_name.is_absolute():
            unpacked_path = self.md_path / self.ABS_UNPACK_DIR / path_name.relative_to('/')
        else:
            unpacked_path = self.md_path / self.REL_UNPACK_DIR / path_name
        return unpacked_path

    def md_for_unpacked_path(self, unpacked_path):
        '''Given an unpacked path, return its MetaDirectory.
        '''
        file_value = self.unpacked_files[unpacked_path]
        md = MetaDirectory.from_md_path(self.meta_root, file_value)
        return md

    def unpacked_md(self, path):
        '''Given a path, return the MetaDirectory for its corresponding unpacked file.
        path is a relative or absolute path, not the unpacked_path.
        '''
        unpacked_path = self.unpacked_path(path)
        return self.md_for_unpacked_path(unpacked_path)

    def make_md_for_file(self, path):
        abs_path = self.meta_root / path
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        md = MetaDirectory(self.meta_root, None, False)
        md.file_path = path
        f = abs_path.open('wb')
        return md, f

    @contextmanager
    def unpack_regular_file(self, path):
        '''Context manager for unpacking a file with path path into the MetaDirectory,
        yields a file object, that you can write to, directly or via sendfile().
        '''
        unpacked_path = self.unpacked_path(path)
        unpacked_md, unpacked_file = self.make_md_for_file(unpacked_path)
        try:
            yield unpacked_md, unpacked_file
        finally:
            unpacked_file.close()
        # update info
        if path.is_absolute():
            self.info.setdefault('unpacked_absolute_files', {})[unpacked_path] = unpacked_md.md_path
        else:
            self.info.setdefault('unpacked_relative_files', {})[unpacked_path] = unpacked_md.md_path
        logging.debug(f'[{self.md_path}]unpack_regular_file: update info to {self.info}')

    def unpack_directory(self, path):
        '''Unpack a directory with path path into the MetaDirectory.
        Returns the path relative to the MetaDirectory.
        '''
        unpacked_path = self.unpacked_path(path)
        full_path = self._meta_root / unpacked_path
        full_path.mkdir(parents=True, exist_ok=True)
        return unpacked_path

    def unpack_symlink(self, source, target):
        '''Unpacks a symlink with path source, pointing to target. The target is not modified
        or rewritten.
        Returns the source path relative to the MetaDirectory.
        '''
        unpacked_path = self.unpacked_path(source)
        full_path = self._meta_root / unpacked_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.symlink_to(target)
        self.info.setdefault('unpacked_symlinks', {})[unpacked_path] = target
        logging.debug(f'[{self.md_path}]unpack_symlink: update info to {self.info}')
        return unpacked_path

    @property
    def unpacked_symlinks(self):
        return self.info.get('unpacked_symlinks',{})

    @property
    def unpacked_files(self):
        return self.unpacked_relative_files | self.unpacked_absolute_files

    @property
    def unpacked_relative_files(self):
        files =  self.info.get('unpacked_relative_files',{})
        logging.debug(f'[{self.md_path}]unpacked_relative_files: got {files}')
        return files

    @property
    def unpacked_absolute_files(self):
        files =  self.info.get('unpacked_absolute_files',{})
        logging.debug(f'[{self.md_path}]unpacked_absolute_files: got {files}')
        return files

    @contextmanager
    def extract_file(self, offset, file_size):
        '''Given offset and file_size, yield a tuple (MetaDirectory, file object) for the
        extracted file.
        '''
        extracted_path = self.extracted_filename(offset, file_size)
        extracted_md, extracted_file = self.make_md_for_file(extracted_path)
        try:
            yield extracted_md, extracted_file
        finally:
            extracted_file.close()
        self.add_extracted_file(extracted_md)

    def add_extracted_file(self, meta_dir):
        '''Adds a MetaDirectory for an extracted file to this MetaDirectory and sets its
        parent.
        '''
        logging.debug(f'[{self.md_path}]add_extracted_file: adding {meta_dir.md_path} for {meta_dir.file_path}')
        self.info.setdefault('extracted_files', {})[meta_dir.file_path] = meta_dir.md_path
        logging.debug(f'[{self.md_path}]add_extracted_file: set info {self.info} for {self.md_path}')
        logging.debug(f'[{self.md_path}]add_extracted_file: setting parent for {meta_dir.md_path} to {self.md_path}')
        with meta_dir.open(open_file=False):
            meta_dir.info['parent_md'] = self.md_path

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

    def extracted_md(self, offset, size):
        '''Given an offset and size, search the MetaDirectory that belongs to an
        extracted file. Raises KeyError if the file does not exist.
        '''
        file_key = self.extracted_filename(offset, size)
        file_value = self.extracted_files[file_key]
        md = MetaDirectory.from_md_path(self.meta_root, file_value)
        return md

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


    def write_info_with_unpack_parser(self):
        '''Let the UnpackParser write metadata to the MetaDirectory.
        '''
        self.unpack_parser.write_info(self)

    def unpack_with_unpack_parser(self):
        '''Let the UnpackParser unpack files to the MetaDirectory.
        '''
        return self.unpack_parser.unpack(self)

