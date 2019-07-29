
from TestUtil import *
from UnpackParserException import UnpackParserException
from UnpackParser import UnpackParser

class InvalidUnpackParser(UnpackParser):
    pass

class TestFileResult(TestBase):
    def test_unpack_parser_without_parse_method(self):
        p = InvalidUnpackParser()
        with self.assertRaisesRegex(UnpackParserException, r"undefined parse method") as cm:
            p.parse()


if __name__ == "__main__":
    unittest.main()
