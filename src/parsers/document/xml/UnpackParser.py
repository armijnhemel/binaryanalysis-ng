
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_xml

class XmlUnpackParser(UnpackParser):
    extensions = ['.xml', '.xsd', '.ncx', '.opf', '.svg']
    signatures = [
    ]
    pretty_name = 'xml'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xml(fileresult, scan_environment, offset, unpack_dir)

