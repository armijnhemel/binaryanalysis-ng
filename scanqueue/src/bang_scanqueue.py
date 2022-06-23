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

import redis

WSGIRequestHandler.protocol_version = "HTTP/1.1"
app = Flask(__name__)
app.config.from_envvar('SCANQUEUE_CONFIGURATION')

if not pathlib.Path(app.config['UPLOAD_DIR']).exists():
    print("upload dir %s does not exist" % app.config['UPLOAD_DIR'], file=sys.stderr)
    sys.exit(1)

if not pathlib.Path(app.config['UPLOAD_DIR']).is_dir():
    print("upload dir %s is not a directory" % app.config['UPLOAD_DIR'], file=sys.stderr)
    sys.exit(1)

# create a connection to Redis
redis_url = 'redis://localhost:6379'

redis_conn = redis.from_url(redis_url)

@app.route("/upload/", methods=['POST'])
def task_post():
    '''Upload a file, return a task id (UUID)'''
    upload_dir = pathlib.Path(app.config['UPLOAD_DIR'])

    # store UUID for any of the files that are uploaded

    # store each file in the upload location
    for f in request.files:
        # create a uuid for the task.
        task_uuid = uuid.uuid4()
        filename = secure_filename(request.files[f].filename)
        uuid_dir = upload_dir / str(task_uuid)
        uuid_dir.mkdir()
        request.files[f].save(upload_dir / str(task_uuid) / filename)
        uuids[filename] = str(task_uuid)

        # store the filename and uuid and status in a Redis hash

        # add the uuid to a task list
    return jsonify(uuids)


@app.route("/status/<task_id>")
def task_status(task_id):
    res = {'match': False}

    # verify if the task_id is a valid UUID
    try:
        task = uuid.UUID(task_id)
    except ValueError:
        return jsonify(res)

    return jsonify(res)
