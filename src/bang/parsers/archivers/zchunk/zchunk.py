# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import IntEnum
import collections


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class Zchunk(KaitaiStruct):
    """
    .. seealso::
       Source - https://github.com/zchunk/zchunk/blob/99e51afa38c723e7c25834c2c3b305d20ef55d04/zchunk_format.txt
    """

    class ChecksumTypes(IntEnum):
        sha1 = 0
        sha256 = 1
        sha512 = 2
        sha512_128 = 3

    class CompressionTypes(IntEnum):
        none = 0
        zstd = 2
    SEQ_FIELDS = ["lead", "header_rest", "dict", "chunks"]
    def __init__(self, _io, _parent=None, _root=None):
        super(Zchunk, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._debug = collections.defaultdict(dict)
        self._read()

    def _read(self):
        self._debug['lead']['start'] = self._io.pos()
        self.lead = Zchunk.HeaderLead(self._io, self, self._root)
        self._debug['lead']['end'] = self._io.pos()
        self._debug['header_rest']['start'] = self._io.pos()
        self._raw_header_rest = self._io.read_bytes(self.lead.len_header_rest.value)
        _io__raw_header_rest = KaitaiStream(BytesIO(self._raw_header_rest))
        self.header_rest = Zchunk.HeaderWithoutLead(_io__raw_header_rest, self, self._root)
        self._debug['header_rest']['end'] = self._io.pos()
        self._debug['dict']['start'] = self._io.pos()
        self.dict = self._io.read_bytes(self.header_rest.index.len_dict.value)
        self._debug['dict']['end'] = self._io.pos()
        if (not (self.lead.is_detached_header)):
            pass
            self._debug['chunks']['start'] = self._io.pos()
            self._debug['chunks']['arr'] = []
            self.chunks = []
            for i in range(len(self.header_rest.index.chunks_metadata)):
                self._debug['chunks']['arr'].append({'start': self._io.pos()})
                self.chunks.append(self._io.read_bytes(self.header_rest.index.chunks_metadata[i].len_chunk.value))
                self._debug['chunks']['arr'][i]['end'] = self._io.pos()

            self._debug['chunks']['end'] = self._io.pos()



    def _fetch_instances(self):
        pass
        self.lead._fetch_instances()
        self.header_rest._fetch_instances()
        if (not (self.lead.is_detached_header)):
            pass
            for i in range(len(self.chunks)):
                pass



    class ChecksumType(KaitaiStruct):
        SEQ_FIELDS = ["raw"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.ChecksumType, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['raw']['start'] = self._io.pos()
            self.raw = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['raw']['end'] = self._io.pos()
            _ = self.raw
            if not self.len_checksum != 0:
                raise kaitaistruct.ValidationExprError(self.raw, self._io, u"/types/checksum_type/seq/0")


        def _fetch_instances(self):
            pass
            self.raw._fetch_instances()

        @property
        def len_checksum(self):
            if hasattr(self, '_m_len_checksum'):
                return self._m_len_checksum

            self._m_len_checksum = (20 if self.value == Zchunk.ChecksumTypes.sha1 else (32 if self.value == Zchunk.ChecksumTypes.sha256 else (64 if self.value == Zchunk.ChecksumTypes.sha512 else (16 if self.value == Zchunk.ChecksumTypes.sha512_128 else 0))))
            return getattr(self, '_m_len_checksum', None)

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value

            self._m_value = KaitaiStream.resolve_enum(Zchunk.ChecksumTypes, self.raw.value)
            return getattr(self, '_m_value', None)


    class Chunk(KaitaiStruct):
        SEQ_FIELDS = ["chunk_stream", "chunk_checksum", "uncompressed_chunk_checksum", "len_chunk", "len_uncompressed_chunk"]
        def __init__(self, len_checksum, has_data_streams, has_uncompressed_source, _io, _parent=None, _root=None):
            super(Zchunk.Chunk, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self.len_checksum = len_checksum
            self.has_data_streams = has_data_streams
            self.has_uncompressed_source = has_uncompressed_source
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            if self.has_data_streams:
                pass
                self._debug['chunk_stream']['start'] = self._io.pos()
                self.chunk_stream = Zchunk.CompressedInteger(self._io, self, self._root)
                self._debug['chunk_stream']['end'] = self._io.pos()

            self._debug['chunk_checksum']['start'] = self._io.pos()
            self.chunk_checksum = self._io.read_bytes(self.len_checksum)
            self._debug['chunk_checksum']['end'] = self._io.pos()
            if self.has_uncompressed_source:
                pass
                self._debug['uncompressed_chunk_checksum']['start'] = self._io.pos()
                self.uncompressed_chunk_checksum = self._io.read_bytes(self.len_checksum)
                self._debug['uncompressed_chunk_checksum']['end'] = self._io.pos()

            self._debug['len_chunk']['start'] = self._io.pos()
            self.len_chunk = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_chunk']['end'] = self._io.pos()
            self._debug['len_uncompressed_chunk']['start'] = self._io.pos()
            self.len_uncompressed_chunk = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_uncompressed_chunk']['end'] = self._io.pos()


        def _fetch_instances(self):
            pass
            if self.has_data_streams:
                pass
                self.chunk_stream._fetch_instances()

            if self.has_uncompressed_source:
                pass

            self.len_chunk._fetch_instances()
            self.len_uncompressed_chunk._fetch_instances()


    class CompressedInteger(KaitaiStruct):
        """Like `/common/vlq_base128_le` (LEB128), but the logic of the
        "continuation" flag in the most significant bit is inverted, so instead of
        `has_next`, it is called `is_last` (if the highest bit is set to zero, it
        means "continue", whereas in standard LEB128, the highest bit set to
        **one** means "continue"). Therefore, we cannot simply import
        `/common/vlq_base128_le` and use it, because it is incompatible.
        """
        SEQ_FIELDS = ["groups"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.CompressedInteger, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['groups']['start'] = self._io.pos()
            self._debug['groups']['arr'] = []
            self.groups = []
            i = 0
            while True:
                self._debug['groups']['arr'].append({'start': self._io.pos()})
                _ = Zchunk.CompressedInteger.Group(i, self._io, self, self._root)
                self.groups.append(_)
                self._debug['groups']['arr'][len(self.groups) - 1]['end'] = self._io.pos()
                if _.is_last:
                    break
                i += 1
            self._debug['groups']['end'] = self._io.pos()


        def _fetch_instances(self):
            pass
            for i in range(len(self.groups)):
                pass
                self.groups[i]._fetch_instances()


        class Group(KaitaiStruct):
            """One byte group, clearly divided into 7-bit "value" chunk and 1-bit "continuation" flag.
            """
            SEQ_FIELDS = ["is_last", "value"]
            def __init__(self, idx, _io, _parent=None, _root=None):
                super(Zchunk.CompressedInteger.Group, self).__init__(_io)
                self._parent = _parent
                self._root = _root
                self.idx = idx
                self._debug = collections.defaultdict(dict)
                self._read()

            def _read(self):
                self._debug['is_last']['start'] = self._io.pos()
                self.is_last = self._io.read_bits_int_be(1) != 0
                self._debug['is_last']['end'] = self._io.pos()
                if not self.is_last == (True if self.idx == 9 else self.is_last):
                    raise kaitaistruct.ValidationNotEqualError((True if self.idx == 9 else self.is_last), self.is_last, self._io, u"/types/compressed_integer/types/group/seq/0")
                self._debug['value']['start'] = self._io.pos()
                self.value = self._io.read_bits_int_be(7)
                self._debug['value']['end'] = self._io.pos()
                if not self.value <= (1 if self.idx == 9 else 127):
                    raise kaitaistruct.ValidationGreaterThanError((1 if self.idx == 9 else 127), self.value, self._io, u"/types/compressed_integer/types/group/seq/1")


            def _fetch_instances(self):
                pass


        @property
        def len(self):
            if hasattr(self, '_m_len'):
                return self._m_len

            self._m_len = len(self.groups)
            return getattr(self, '_m_len', None)

        @property
        def value(self):
            """Resulting unsigned value as normal integer."""
            if hasattr(self, '_m_value'):
                return self._m_value

            self._m_value = (((((((((self.groups[0].value | (self.groups[1].value << 7 if self.len >= 2 else 0)) | (self.groups[2].value << 14 if self.len >= 3 else 0)) | (self.groups[3].value << 21 if self.len >= 4 else 0)) | (self.groups[4].value << 28 if self.len >= 5 else 0)) | (self.groups[5].value << 35 if self.len >= 6 else 0)) | (self.groups[6].value << 42 if self.len >= 7 else 0)) | (self.groups[7].value << 49 if self.len >= 8 else 0)) | (self.groups[8].value << 56 if self.len >= 9 else 0)) | (self.groups[9].value << 63 if self.len >= 10 else 0))
            return getattr(self, '_m_value', None)


    class HeaderLead(KaitaiStruct):
        SEQ_FIELDS = ["magic", "overall_checksum_type", "len_header_rest", "header_checksum"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.HeaderLead, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['magic']['start'] = self._io.pos()
            self.magic = self._io.read_bytes(5)
            self._debug['magic']['end'] = self._io.pos()
            if not  ((self.magic == b"\x00\x5A\x43\x4B\x31") or (self.magic == b"\x00\x5A\x48\x52\x31")) :
                raise kaitaistruct.ValidationNotAnyOfError(self.magic, self._io, u"/types/header_lead/seq/0")
            self._debug['overall_checksum_type']['start'] = self._io.pos()
            self.overall_checksum_type = Zchunk.ChecksumType(self._io, self, self._root)
            self._debug['overall_checksum_type']['end'] = self._io.pos()
            self._debug['len_header_rest']['start'] = self._io.pos()
            self.len_header_rest = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_header_rest']['end'] = self._io.pos()
            self._debug['header_checksum']['start'] = self._io.pos()
            self.header_checksum = self._io.read_bytes(self.overall_checksum_type.len_checksum)
            self._debug['header_checksum']['end'] = self._io.pos()


        def _fetch_instances(self):
            pass
            self.overall_checksum_type._fetch_instances()
            self.len_header_rest._fetch_instances()

        @property
        def is_detached_header(self):
            """Determines whether this file is a zchunk detached header (`.zhr`). If
            not, it is a complete zchunk file (`.zck`).
            """
            if hasattr(self, '_m_is_detached_header'):
                return self._m_is_detached_header

            self._m_is_detached_header = KaitaiStream.byte_array_index(self.magic, 2) == 72
            return getattr(self, '_m_is_detached_header', None)


    class HeaderWithoutLead(KaitaiStruct):
        SEQ_FIELDS = ["preface", "len_index", "index", "num_signatures"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.HeaderWithoutLead, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['preface']['start'] = self._io.pos()
            self.preface = Zchunk.Preface(self._io, self, self._root)
            self._debug['preface']['end'] = self._io.pos()
            self._debug['len_index']['start'] = self._io.pos()
            self.len_index = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_index']['end'] = self._io.pos()
            self._debug['index']['start'] = self._io.pos()
            self._raw_index = self._io.read_bytes(self.len_index.value)
            _io__raw_index = KaitaiStream(BytesIO(self._raw_index))
            self.index = Zchunk.Index(_io__raw_index, self, self._root)
            self._debug['index']['end'] = self._io.pos()
            self._debug['num_signatures']['start'] = self._io.pos()
            self.num_signatures = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['num_signatures']['end'] = self._io.pos()
            _ = self.num_signatures
            if not _.value == 0:
                raise kaitaistruct.ValidationExprError(self.num_signatures, self._io, u"/types/header_without_lead/seq/3")


        def _fetch_instances(self):
            pass
            self.preface._fetch_instances()
            self.len_index._fetch_instances()
            self.index._fetch_instances()
            self.num_signatures._fetch_instances()


    class Index(KaitaiStruct):
        SEQ_FIELDS = ["chunk_checksum_type", "num_chunks", "dict_stream", "dict_checksum", "uncompressed_dict_checksum", "len_dict", "len_uncompressed_dict", "chunks_metadata"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.Index, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['chunk_checksum_type']['start'] = self._io.pos()
            self.chunk_checksum_type = Zchunk.ChecksumType(self._io, self, self._root)
            self._debug['chunk_checksum_type']['end'] = self._io.pos()
            self._debug['num_chunks']['start'] = self._io.pos()
            self.num_chunks = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['num_chunks']['end'] = self._io.pos()
            _ = self.num_chunks
            if not _.value >= 1:
                raise kaitaistruct.ValidationExprError(self.num_chunks, self._io, u"/types/index/seq/1")
            if self._parent.preface.has_data_streams:
                pass
                self._debug['dict_stream']['start'] = self._io.pos()
                self.dict_stream = Zchunk.CompressedInteger(self._io, self, self._root)
                self._debug['dict_stream']['end'] = self._io.pos()
                _ = self.dict_stream
                if not _.value == 0:
                    raise kaitaistruct.ValidationExprError(self.dict_stream, self._io, u"/types/index/seq/2")

            self._debug['dict_checksum']['start'] = self._io.pos()
            self.dict_checksum = self._io.read_bytes(self.chunk_checksum_type.len_checksum)
            self._debug['dict_checksum']['end'] = self._io.pos()
            if self._parent.preface.has_uncompressed_source:
                pass
                self._debug['uncompressed_dict_checksum']['start'] = self._io.pos()
                self.uncompressed_dict_checksum = self._io.read_bytes(self.chunk_checksum_type.len_checksum)
                self._debug['uncompressed_dict_checksum']['end'] = self._io.pos()

            self._debug['len_dict']['start'] = self._io.pos()
            self.len_dict = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_dict']['end'] = self._io.pos()
            self._debug['len_uncompressed_dict']['start'] = self._io.pos()
            self.len_uncompressed_dict = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_uncompressed_dict']['end'] = self._io.pos()
            self._debug['chunks_metadata']['start'] = self._io.pos()
            self._debug['chunks_metadata']['arr'] = []
            self.chunks_metadata = []
            for i in range(self.num_data_chunks):
                self._debug['chunks_metadata']['arr'].append({'start': self._io.pos()})
                self.chunks_metadata.append(Zchunk.Chunk(self.chunk_checksum_type.len_checksum, self._parent.preface.has_data_streams, self._parent.preface.has_uncompressed_source, self._io, self, self._root))
                self._debug['chunks_metadata']['arr'][i]['end'] = self._io.pos()

            self._debug['chunks_metadata']['end'] = self._io.pos()


        def _fetch_instances(self):
            pass
            self.chunk_checksum_type._fetch_instances()
            self.num_chunks._fetch_instances()
            if self._parent.preface.has_data_streams:
                pass
                self.dict_stream._fetch_instances()

            if self._parent.preface.has_uncompressed_source:
                pass

            self.len_dict._fetch_instances()
            self.len_uncompressed_dict._fetch_instances()
            for i in range(len(self.chunks_metadata)):
                pass
                self.chunks_metadata[i]._fetch_instances()


        @property
        def num_data_chunks(self):
            """Number of data chunks. `num_chunks` counts the dictionary as chunk 0,
            so it is one greater than this number.
            """
            if hasattr(self, '_m_num_data_chunks'):
                return self._m_num_data_chunks

            self._m_num_data_chunks = self.num_chunks.value - 1
            return getattr(self, '_m_num_data_chunks', None)


    class OptionalElement(KaitaiStruct):
        SEQ_FIELDS = ["element_id", "len_data", "data"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.OptionalElement, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['element_id']['start'] = self._io.pos()
            self.element_id = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['element_id']['end'] = self._io.pos()
            self._debug['len_data']['start'] = self._io.pos()
            self.len_data = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['len_data']['end'] = self._io.pos()
            self._debug['data']['start'] = self._io.pos()
            self.data = self._io.read_bytes(self.len_data.value)
            self._debug['data']['end'] = self._io.pos()


        def _fetch_instances(self):
            pass
            self.element_id._fetch_instances()
            self.len_data._fetch_instances()


    class Preface(KaitaiStruct):
        SEQ_FIELDS = ["data_checksum", "flags", "compression_type_int", "num_optional_elements", "optional_elements"]
        def __init__(self, _io, _parent=None, _root=None):
            super(Zchunk.Preface, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._debug = collections.defaultdict(dict)
            self._read()

        def _read(self):
            self._debug['data_checksum']['start'] = self._io.pos()
            self.data_checksum = self._io.read_bytes(self._root.lead.overall_checksum_type.len_checksum)
            self._debug['data_checksum']['end'] = self._io.pos()
            self._debug['flags']['start'] = self._io.pos()
            self.flags = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['flags']['end'] = self._io.pos()
            _ = self.flags
            if not _.value <= 7:
                raise kaitaistruct.ValidationExprError(self.flags, self._io, u"/types/preface/seq/1")
            self._debug['compression_type_int']['start'] = self._io.pos()
            self.compression_type_int = Zchunk.CompressedInteger(self._io, self, self._root)
            self._debug['compression_type_int']['end'] = self._io.pos()
            _ = self.compression_type_int
            if not  ((_.value == int(Zchunk.CompressionTypes.none)) or (_.value == int(Zchunk.CompressionTypes.zstd))) :
                raise kaitaistruct.ValidationExprError(self.compression_type_int, self._io, u"/types/preface/seq/2")
            if self.has_optional_elements:
                pass
                self._debug['num_optional_elements']['start'] = self._io.pos()
                self.num_optional_elements = Zchunk.CompressedInteger(self._io, self, self._root)
                self._debug['num_optional_elements']['end'] = self._io.pos()
                _ = self.num_optional_elements
                if not _.value >= 1:
                    raise kaitaistruct.ValidationExprError(self.num_optional_elements, self._io, u"/types/preface/seq/3")

            if self.has_optional_elements:
                pass
                self._debug['optional_elements']['start'] = self._io.pos()
                self._debug['optional_elements']['arr'] = []
                self.optional_elements = []
                for i in range(self.num_optional_elements.value):
                    self._debug['optional_elements']['arr'].append({'start': self._io.pos()})
                    self.optional_elements.append(Zchunk.OptionalElement(self._io, self, self._root))
                    self._debug['optional_elements']['arr'][i]['end'] = self._io.pos()

                self._debug['optional_elements']['end'] = self._io.pos()



        def _fetch_instances(self):
            pass
            self.flags._fetch_instances()
            self.compression_type_int._fetch_instances()
            if self.has_optional_elements:
                pass
                self.num_optional_elements._fetch_instances()

            if self.has_optional_elements:
                pass
                for i in range(len(self.optional_elements)):
                    pass
                    self.optional_elements[i]._fetch_instances()



        @property
        def compression_type(self):
            if hasattr(self, '_m_compression_type'):
                return self._m_compression_type

            self._m_compression_type = KaitaiStream.resolve_enum(Zchunk.CompressionTypes, self.compression_type_int.value)
            return getattr(self, '_m_compression_type', None)

        @property
        def has_data_streams(self):
            if hasattr(self, '_m_has_data_streams'):
                return self._m_has_data_streams

            self._m_has_data_streams = self.flags.value & 1 != 0
            return getattr(self, '_m_has_data_streams', None)

        @property
        def has_optional_elements(self):
            if hasattr(self, '_m_has_optional_elements'):
                return self._m_has_optional_elements

            self._m_has_optional_elements = self.flags.value & 2 != 0
            return getattr(self, '_m_has_optional_elements', None)

        @property
        def has_uncompressed_source(self):
            """The file may be applied against an uncompressed source. This adds an
            uncompressed checksum to every index entry, including the dictionary.
            """
            if hasattr(self, '_m_has_uncompressed_source'):
                return self._m_has_uncompressed_source

            self._m_has_uncompressed_source = self.flags.value & 4 != 0
            return getattr(self, '_m_has_uncompressed_source', None)



