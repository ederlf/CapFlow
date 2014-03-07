#!/usr/bin/env python
#-*- coding:utf-8 -*-

# WARNING: this web application is just a toy and should not be used for
# production purposes.

# TODO: make a more serious and configurable web application. It could even be
# based on this one.

from cgi import parse_qs, escape
import json
import urlparse
from wsgiref.util import shift_path_info
import os
import os.path
import urllib

import sys
sys.path.append("../")

PLAIN = 0
HTML = 1
JSON = 2
CSS = 3
JS = 4
GIF = 5
PNG = 6
JPEG = 7

CONTENT_TYPES = {
PLAIN: "text/plain",
HTML: "text/html",
JSON: "application/json",
CSS: "text/css",
JS: "text/javascript",
GIF: "image/gif",
PNG: "image/png",
JPEG: "image/jpeg",
}

exts = {
".js": JS,
".html": HTML,
".css": CSS,
".png": PNG,
".gif": GIF,
".jpg": JPEG,
".jpeg": JPEG,
".json": JSON,
}

USERS = {
    "eder": "abc",
    "allan": "def",
    "test": "test"
}


def reply(start_response, status_code, ctype=None, content=None):
    if ctype is not None:
        start_response(status_code, [("Content-Type", CONTENT_TYPES[ctype]),
                                     ("Content-Length", str(len(content)))])
    else:
        start_response(status_code, [])

    if content is None:
        return []
    return content


def redirect(start_response, destination):
    start_response('303 See Other',  [("Location", destination)])
    return []


def application(env, start_response):
    #print env
    old_path = env["PATH_INFO"]
    path = shift_path_info(env)
    request = parse_qs(env["QUERY_STRING"])
    try:
        callback = request["callback"][0]
    except KeyError:
        callback = None

    status = 404
    rbody = ""
    ctype = PLAIN

    print "path:'%s'" % path
    if path == "auth":
        if "CONTENT_LENGTH" in env:
            try:
                len_ = int(env["CONTENT_LENGTH"])
                body = env['wsgi.input'].read(len_)
            except ValueError:
                return reply(start_response, "400 Bad Request", PLAIN,
                             "Missing login information.")

            request = parse_qs(body)
            try:
                username = request["username"][0]
                password = request["password"][0]
                redirect_target = request["redirect"][0]
            except KeyError, IndexError:
                return reply(start_response, "400 Bad Request",
                             "Missing login information.")
            if username not in USERS or USERS[username] != password:
                return reply(start_response, "401 Unauthorized", PLAIN,
                             "Unauthorized access.")
            text = (
                "Authenticated. "
                "Redirecting to <a href='%(url)s'>%(url)s</a> in 10 seconds. "
                "<meta http-equiv='refresh' content='10;%(url)s'>"
                ) % {'url': escape(redirect_target)}
            return reply(start_response, "200 OK", HTML, text)
    elif path == "login":
        request = parse_qs(env["QUERY_STRING"])
        content = open("login.html", "r").read()
        content = content % {"redirect": request['redirect'][0]}
        return reply(start_response, "200 OK", HTML, content)
    else:
        # Return file
        path = os.path.join(os.getcwd(), path + env["PATH_INFO"])
        if os.path.exists(path) and os.path.isfile(path):
            f = open(path, "r")
            rbody = f.read()
            ctype = exts[os.path.splitext(path)[1]]
            f.close()
            return reply(start_response, "200 OK", ctype, rbody)
        # Couldn't find path, redirect to login
        else:
            target = urllib.urlencode({
                "redirect": "http://" + env["HTTP_HOST"] + "/" + old_path +
                env["PATH_INFO"] + "?" + env["QUERY_STRING"]
            })
            print target
            return redirect(start_response, "/login?%s" % target)
