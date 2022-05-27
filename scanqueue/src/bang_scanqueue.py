#!/usr/bin/env python3
#
# Copyright 2022 - Armijn Hemel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import pathlib
import sys
import uuid

from flask import Flask

from flask import abort, jsonify, request

from werkzeug.serving import WSGIRequestHandler
from werkzeug.utils import secure_filename

WSGIRequestHandler.protocol_version = "HTTP/1.1"
app = Flask(__name__)
app.config.from_prefixed_env()

@app.route("/upload/", methods=['POST'])
def task_post():
    '''Upload a file, return a task id'''
    upload_dir = pathlib.Path('/home/armijn/upload')

    uuids = {}

    for f in request.files:
        task_uuid = uuid.uuid4()
        filename = secure_filename(request.files[f].filename)
        uuid_dir = upload_dir / str(task_uuid)
        uuid_dir.mkdir()
        request.files[f].save(upload_dir / str(task_uuid) / filename)
        uuids[filename] = str(task_uuid)
    return jsonify(uuids)


@app.route("/status/<task_id>")
def task_status(task_id):
    res = {'match': False}

    return jsonify(res)
