
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_xml

class XmlUnpackParser(WrappedUnpackParser):
    extensions = ['.xml', '.xsd', '.ncx', '.opf', '.svg']
    signatures = [
    ]
    pretty_name = 'xml'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xml(fileresult, scan_environment, offset, unpack_dir)

