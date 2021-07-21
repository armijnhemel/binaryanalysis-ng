
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_ssh_known_hosts

class SshKnownHostsUnpackParser(WrappedUnpackParser):
    extensions = ['ssh_known_hosts', 'known_hosts']
    signatures = [
    ]
    pretty_name = 'ssh_known_hosts'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ssh_known_hosts(fileresult, scan_environment, offset, unpack_dir)

