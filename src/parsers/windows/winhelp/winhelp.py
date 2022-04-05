# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Winhelp(KaitaiStruct):
    """
    .. seealso::
       Source - http://www.oocities.org/mwinterhoff/helpfile.htm
    """

    class FormatVersion(Enum):
        windows_30 = 15
        windows_31 = 21
        media_view = 27
        windows_95 = 33

    class SystemRecordTypes(Enum):
        title = 1
        copyright = 2
        contents = 3
        config = 4
        icon = 5
        window = 6
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.magic = self._io.read_bytes(4)
        if not self.magic == b"\x3F\x5F\x03\x00":
            raise kaitaistruct.ValidationNotEqualError(b"\x3F\x5F\x03\x00", self.magic, self._io, u"/seq/0")
        self.ofs_internal_directory = self._io.read_u4le()
        self.ofs_first_free_block = self._io.read_s4le()
        self.len_file = self._io.read_u4le()

    class LeafPage(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.num_unused = self._io.read_u2le()
            self.num_entries = self._io.read_u2le()
            self.previous_leaf_page = self._io.read_s2le()
            self.next_leaf_page = self._io.read_s2le()
            self.entries = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self.entries[i] = Winhelp.LeafEntry(self._io, self, self._root)



    class System(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(2)
            if not self.magic == b"\x6C\x03":
                raise kaitaistruct.ValidationNotEqualError(b"\x6C\x03", self.magic, self._io, u"/types/system/seq/0")
            self.minor = KaitaiStream.resolve_enum(Winhelp.FormatVersion, self._io.read_u2le())
            if not  ((self.minor == Winhelp.FormatVersion.windows_31)) :
                raise kaitaistruct.ValidationNotAnyOfError(self.minor, self._io, u"/types/system/seq/1")
            self.major = self._io.read_u2le()
            if not self.major == 1:
                raise kaitaistruct.ValidationNotEqualError(1, self.major, self._io, u"/types/system/seq/2")
            self.date = self._io.read_u4le()
            self.flags = self._io.read_u2le()
            self.system_records = []
            i = 0
            while not self._io.is_eof():
                self.system_records.append(Winhelp.System.SystemRecord(self._io, self, self._root))
                i += 1


        class SystemRecord(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.record_type = KaitaiStream.resolve_enum(Winhelp.SystemRecordTypes, self._io.read_u2le())
                self.len_data = self._io.read_u2le()
                _on = self.record_type
                if _on == Winhelp.SystemRecordTypes.copyright:
                    self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.len_data), 0, False)).decode(u"ASCII")
                elif _on == Winhelp.SystemRecordTypes.window:
                    self._raw_data = self._io.read_bytes(self.len_data)
                    _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                    self.data = Winhelp.System.Window(_io__raw_data, self, self._root)
                elif _on == Winhelp.SystemRecordTypes.config:
                    self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.len_data), 0, False)).decode(u"ASCII")
                elif _on == Winhelp.SystemRecordTypes.title:
                    self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.len_data), 0, False)).decode(u"ASCII")
                else:
                    self.data = self._io.read_bytes(self.len_data)


        class Window(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.flags = self._io.read_u2le()
                self.window_type = self._io.read_bytes(10)
                self.name = self._io.read_bytes(9)
                self.caption = self._io.read_bytes(51)
                self.x_coordinate = self._io.read_u2le()
                self.y_coordinate = self._io.read_u2le()
                self.width = self._io.read_u2le()
                self.height = self._io.read_u2le()
                self.maximize = self._io.read_u2le()



    class LeafEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.filename = (self._io.read_bytes_term(0, False, True, True)).decode(u"ASCII")
            self.ofs_fileheader = self._io.read_u4le()

        @property
        def file(self):
            if hasattr(self, '_m_file'):
                return self._m_file if hasattr(self, '_m_file') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.ofs_fileheader)
            self._m_file = Winhelp.FileData(self.filename, io, self, self._root)
            io.seek(_pos)
            return self._m_file if hasattr(self, '_m_file') else None


    class Font(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.num_face_names = self._io.read_u2le()
            self.num_descriptors = self._io.read_u2le()
            self.ofs_facenames = self._io.read_u2le()
            self.ofs_descriptors = self._io.read_u2le()
            if self.ofs_facenames >= 12:
                self.num_styles = self._io.read_u2le()

            if self.ofs_facenames >= 12:
                self.ofs_styles = self._io.read_u2le()

            if self.ofs_facenames >= 16:
                self.num_char_map_tables = self._io.read_u2le()

            if self.ofs_facenames >= 16:
                self.ofs_char_map_tables = self._io.read_u2le()



    class InternalDirectory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.header = Winhelp.FileHeader(self._io, self, self._root)
            self._raw_contents = self._io.read_bytes(self.header.len_used_space)
            _io__raw_contents = KaitaiStream(BytesIO(self._raw_contents))
            self.contents = Winhelp.BTree(_io__raw_contents, self, self._root)
            self.free_space = self._io.read_bytes(((self.header.len_reserved_space - self.header.len_used_space) - 9))


    class BTree(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(2)
            if not self.magic == b"\x3B\x29":
                raise kaitaistruct.ValidationNotEqualError(b"\x3B\x29", self.magic, self._io, u"/types/b_tree/seq/0")
            self.flags = self._io.read_u2le()
            self.page_size = self._io.read_u2le()
            self.structure = (KaitaiStream.bytes_terminate(self._io.read_bytes(16), 0, False)).decode(u"ASCII")
            self.zero = self._io.read_u2le()
            if not self.zero == 0:
                raise kaitaistruct.ValidationNotEqualError(0, self.zero, self._io, u"/types/b_tree/seq/4")
            self.page_splits = self._io.read_u2le()
            self.root_page = self._io.read_u2le()
            self.negative_one = self._io.read_s2le()
            if not self.negative_one == -1:
                raise kaitaistruct.ValidationNotEqualError(-1, self.negative_one, self._io, u"/types/b_tree/seq/7")
            self.num_pages = self._io.read_u2le()
            self.num_levels = self._io.read_u2le()
            self.num_entries = self._io.read_u4le()
            self.pages = [None] * ((self.num_pages - 1))
            for i in range((self.num_pages - 1)):
                self.pages[i] = self._io.read_bytes(self.page_size)

            self._raw_leaf_page = self._io.read_bytes(self.page_size)
            _io__raw_leaf_page = KaitaiStream(BytesIO(self._raw_leaf_page))
            self.leaf_page = Winhelp.LeafPage(_io__raw_leaf_page, self, self._root)


    class FileData(KaitaiStruct):
        def __init__(self, filename, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.filename = filename
            self._read()

        def _read(self):
            self.header = Winhelp.FileHeader(self._io, self, self._root)
            _on = self.filename
            if _on == u"|CTXOMAP":
                self._raw_body = self._io.read_bytes(self.header.len_used_space)
                _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
                self.body = Winhelp.Ctxomap(_io__raw_body, self, self._root)
            elif _on == u"|FONT":
                self._raw_body = self._io.read_bytes(self.header.len_used_space)
                _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
                self.body = Winhelp.Font(_io__raw_body, self, self._root)
            elif _on == u"|SYSTEM":
                self._raw_body = self._io.read_bytes(self.header.len_used_space)
                _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
                self.body = Winhelp.System(_io__raw_body, self, self._root)
            else:
                self.body = self._io.read_bytes(self.header.len_used_space)
            self.free_space = self._io.read_bytes(((self.header.len_reserved_space - self.header.len_used_space) - 9))


    class Ctxomap(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.num_entries = self._io.read_u2le()
            self.entries = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self.entries[i] = Winhelp.Ctxomap.CtxoMapEntry(self._io, self, self._root)


        class CtxoMapEntry(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.map_id = self._io.read_u4le()
                self.ofs_topic = self._io.read_u4le()



    class FileHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len_reserved_space = self._io.read_u4le()
            self.len_used_space = self._io.read_u4le()
            self.file_flags = self._io.read_u1()


    @property
    def internal_directory(self):
        if hasattr(self, '_m_internal_directory'):
            return self._m_internal_directory if hasattr(self, '_m_internal_directory') else None

        _pos = self._io.pos()
        self._io.seek(self.ofs_internal_directory)
        self._m_internal_directory = Winhelp.InternalDirectory(self._io, self, self._root)
        self._io.seek(_pos)
        return self._m_internal_directory if hasattr(self, '_m_internal_directory') else None


