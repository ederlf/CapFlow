# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
# Copyright (C) 2014 Joe Stringer < joe at wand net nz >
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import re
import socket

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication


class UserController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(UserController, self).__init__(req, link, data, **config)
        self.authenticate = data

    @staticmethod
    def register(wsgi):
        route_name = 'authenticate'
        uri = '/v1.0/authenticate'
        wsgi.mapper.connect(route_name, uri,
                            controller=UserController, action='list',
                            conditions=dict(method=['GET', 'HEAD']))

        uri += '/{ip}'
        s = wsgi.mapper.submapper(controller=UserController)
        s.connect(route_name, uri, action='post',
                  conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='put',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='delete',
                  conditions=dict(method=['DELETE']))

    @staticmethod
    def validate(address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def list(self, req, **_kwargs):
        body = json.dumps(self.authenticate)
        return Response(content_type='application/json', body=body)

    def post(self, req, ip, **_kwargs):
        if not self.validate(ip):
            return Response(status=403)
        if self.authenticate[ip] == True:
            return Response(status=409)

        self.authenticate[ip] = True
        return Response(status=200)

    def put(self, req, ip, **_kwargs):
        if not self.validate(ip):
            return Response(status=403)

        self.authenticate[ip] = True
        return Response(status=200)

    def delete(self, req, ip, **_kwargs):
        if self.authenticate[ip] != True:
            return Response(status=404)

        del self.authenticate[ip]
        return Response(status=200)
