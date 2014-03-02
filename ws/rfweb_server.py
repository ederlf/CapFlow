from wsgiref.simple_server import make_server
import rfweb

httpd = make_server("0.0.0.0", 80, rfweb.application)
print "Serving on 0.0.0.0:80"
httpd.serve_forever()
