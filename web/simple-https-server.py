# https://blog.anvileight.com/posts/simple-python-http-server/#python-3-x

from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl


host =('localhost', 4443)
httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="localhost.key", 
        certfile='localhost.crt', server_side=True)

print('serving on ', host)
httpd.serve_forever()
