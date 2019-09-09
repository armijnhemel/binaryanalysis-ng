
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
        p = InvalidUnpackParser()
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
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        p = SqliteUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)

    def test_unpackparser_raises_exception(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        p = GifUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)



 
if __name__ == "__main__":
    unittest.main()
