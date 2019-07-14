# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3, as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright 2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import copy
import elasticsearch

class ElasticsearchReporter:
    def __init__(self, environment):
        self.environment = environment
    def report(self, scanresult):
        '''Put results into Elasticsearch'''
        # copy scanresult because json cannot serialize datetime objects by itself
        result = copy.deepcopy(scanresult)

        # pretty print datetime formats first before serializing
        result['session']['start'] = result['session']['start'].isoformat()
        result['session']['stop'] = result['session']['stop'].isoformat()

        # store the scan uuid in URN (RFC 4122) form
        result['session']['uuid'] = result['session']['uuid'].urn

        uuid = result['session']['uuid']

        # first create the Elasticsearch connection string. TODO: sanitize
        connectionstring = 'http://%s:%s@%s:%d/'

        if self.environment['elastic_port'] is None:
            elastic_port = 9200
        else:
            elastic_port = self.environment['elastic_port']

        if self.environment['elastic_host'] is None:
            elastic_host = 'localhost'
        else:
            elastic_host = self.environment['elastic_host']

        if self.environment['elastic_index'] is None:
            elastic_index = ''
        else:
            elastic_index = self.environment['elastic_index']

        if self.environment['elastic_user'] is None:
            elastic_user = ''
        else:
            elastic_user = self.environment['elastic_user']

        if self.environment['elastic_password'] is None:
            elastic_password = ''
        else:
            elastic_password = self.environment['elastic_password']

        connectionstring = connectionstring % (elastic_user, elastic_password, elastic_host, elastic_port)

        es = elasticsearch.Elasticsearch([connectionstring])

        # store some information about the session
        es.index(index=elastic_index, doc_type='_doc', body=result['session'])

        # store information about the individual nodes.
        # TODO: use the bulk interface for this
        for scannode in result['scantree']:
            scannode_res = result['scantree'][scannode]
            scannode_res['uuid'] = uuid
            es.index(index=elastic_index, doc_type='_doc', body=scannode_res)
