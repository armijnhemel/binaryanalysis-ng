# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class GimpBrush(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header_size = self._io.read_u4be()
        self.version = self._io.read_u4be()
        self.width = self._io.read_u4be()
        self.height = self._io.read_u4be()
        self.color_depth = self._io.read_u4be()
        self.magic = self._io.read_bytes(4)
        if not self.magic == b"\x47\x49\x4D\x50":
            raise kaitaistruct.ValidationNotEqualError(b"\x47\x49\x4D\x50", self.magic, self._io, u"/seq/5")
        self.spacing = self._io.read_u4be()
        self.brush_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(((self.header_size - 1) - 28)), 0, False)).decode(u"UTF-8")

    @property
    def body_size(self):
        if hasattr(self, '_m_body_size'):
            return self._m_body_size if hasattr(self, '_m_body_size') else None

        self._m_body_size = ((self.width * self.height) * self.color_depth)
        return self._m_body_size if hasattr(self, '_m_body_size') else None

    @property
    def body(self):
        if hasattr(self, '_m_body'):
            return self._m_body if hasattr(self, '_m_body') else None

        _pos = self._io.pos()
        self._io.seek(self.header_size)
        self._m_body = self._io.read_bytes(self.body_size)
        self._io.seek(_pos)
        return self._m_body if hasattr(self, '_m_body') else None


