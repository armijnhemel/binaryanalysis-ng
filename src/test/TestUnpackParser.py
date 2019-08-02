
from TestUtil import *
from UnpackParserException import UnpackParserException
from UnpackParser import UnpackParser
from bangsignatures import get_unpackers

class InvalidUnpackParser(UnpackParser):
    pass

class TestFileResult(TestBase):
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
                self.assertEquals(type(s_text),type(b''))

if __name__ == "__main__":
    unittest.main()
