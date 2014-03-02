from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime

def get_redirect():
    now = datetime.now()
    stamp = mktime(now.timetuple())

    response="""HTTP/1.0 303 See Other\r\nDate: {}\r\nServer: WSGIServer/0.1 Python/2.7.3\r\nLocation: http://192.168.17.1/login.html\r\nContent-Length: 0\r\n\r\n"""

    return response.format(format_date_time(stamp))
    
print get_redirect()
