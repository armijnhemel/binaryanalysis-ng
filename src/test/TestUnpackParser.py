
from parameterized import parameterized
from .TestUtil import *
from UnpackParserException import UnpackParserException
from UnpackParser import UnpackParser
from bangsignatures import get_unpackers
from parsers.database.sqlite.UnpackParser import SqliteUnpackParser
from parsers.image.gif.UnpackParser import GifUnpackParser

class InvalidUnpackParser(UnpackParser):
    pass

class TestUnpackParser(TestBase):
    def test_unpack_parser_without_parse_method(self):
        p = InvalidUnpackParser(None, None, None, 0)
        with self.assertRaisesRegex(UnpackParserException, r"undefined parse method") as cm:
            p.parse()

    def test_unpackparser_list_has_derived_classes_only(self):
        self.assertNotIn(UnpackParser, get_unpackers())

    def test_all_unpack_parsers_have_attributes(self):
        for unpackparser in get_unpackers():
            self.assertIsNotNone(unpackparser.pretty_name)
            self.assertIsNotNone(unpackparser.extensions)
            self.assertIsNotNone(unpackparser.signatures)
            # assert all signatures are bytestrings
            i = 0
            for s_offset, s_text in unpackparser.signatures:
                self.assertEqual(type(s_text),type(b''))

    def test_unpackparsers_are_found(self):
        unpacker_names = [ u.__name__ for u in get_unpackers() ]
        self.assertIn('GifUnpackParser', unpacker_names)
        self.assertIn('VfatUnpackParser', unpacker_names)


    def test_wrapped_unpackparser_raises_exception(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, SqliteUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack()
        p.close()

    def test_unpackparser_raises_exception(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, GifUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack()
        p.close()

    @parameterized.expand([ (u,) for u in get_unpackers() ])
    def test_all_unpack_parsers_raise_exception_on_empty_file(self, unpackparser):
        rel_testfile = pathlib.Path('unpackers') / 'empty'
        # for unpackparser in get_unpackers():
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        up = self.create_unpackparser_for_path(rel_testfile,
                unpackparser, 0, data_unpack_dir = data_unpack_dir)
        up.open()
        with self.assertRaisesRegex(UnpackParserException, r".*",
                msg=unpackparser.__name__) as cm:
            r = up.parse_and_unpack()
        up.close()

 

 
if __name__ == "__main__":
    unittest.main()
