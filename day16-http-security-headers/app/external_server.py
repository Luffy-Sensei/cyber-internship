from http.server import BaseHTTPRequestHandler, HTTPServer


SCRIPT = b"""
console.log("CSP TEST: Disallowed cross-origin script executed.");
"""


class ExternalScriptHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/external.js":
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/javascript"
            )
            self.send_header(
                "Content-Length",
                str(len(SCRIPT))
            )
            self.end_headers()

            self.wfile.write(SCRIPT)

        else:
            self.send_response(404)
            self.end_headers()


def run_server():
    server_address = ("127.0.0.1", 9000)

    httpd = HTTPServer(
        server_address,
        ExternalScriptHandler
    )

    print("[*] CSP External-Origin Test Server")
    print("[*] Server: http://127.0.0.1:9000")
    print("[*] Environment: Authorized Localhost Testing")
    print("[*] Press CTRL+C to stop")

    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
