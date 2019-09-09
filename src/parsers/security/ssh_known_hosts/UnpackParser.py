
import os
from UnpackParser import UnpackParser
from bangtext import unpack_ssh_known_hosts

class SshKnownHostsUnpackParser(UnpackParser):
    extensions = ['ssh_known_hosts', 'known_hosts']
    signatures = [
    ]
    pretty_name = 'ssh_known_hosts'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ssh_known_hosts(fileresult, scan_environment, offset, unpack_dir)

