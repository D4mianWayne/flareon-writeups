#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
from email.utils import formatdate

RESPONSE_JSON = {
    "d": "085d8ea282da6cf76bb2765bc3b26549a1f6bdf08d8da2a62e05ad96ea645c685da48d66ed505e2e28b968d15dabed15ab1500901eb9da4606468650f72550483f1e8c58ca13136bb8028f976bedd36757f705ea5f74ace7bd8af941746b961c45bcac1eaf589773cecf6f1c620e0e37ac1dfc9611aa8ae6e6714bb79a186f47896f18203eddce97f496b71a630779b136d7bf0c82d560"
}

class CustomHandler(BaseHTTPRequestHandler):
    server_version = "SimpleHTTP/0.6 Python/3.10.11"
    sys_version = ""   # avoid default Python/x.y.z suffix
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        if self.path == "/good":
            body = json.dumps(RESPONSE_JSON, separators=(',', ':')).encode("utf-8")
            self.send_response(200, "OK")
            self.send_header("Server", self.server_version)
            # RFC-compliant date header
            self.send_header("Date", formatdate(timeval=None, localtime=False, usegmt=True))
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")

def run(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, CustomHandler)
    print(f"Serving on http://localhost:{port}/good")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    run()
