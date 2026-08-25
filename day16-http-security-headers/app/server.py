from http.server import BaseHTTPRequestHandler, HTTPServer


BODY = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Day 16 CSP Lab</title>
</head>
<body>
    <h1>HTTP Security Header Analysis Lab</h1>

    <p>Authorized localhost testing environment.</p>

    <script src="/static/allowed.js"></script>
    <script src="http://127.0.0.1:9000/external.js"></script>
</body>
</html>
""".encode("utf-8")


class SecurityHeaderLabHandler(BaseHTTPRequestHandler):

    def send_security_headers(self):
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'"
        )

        self.send_header(
            "X-Frame-Options",
            "DENY"
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "Strict-Transport-Security",
            "max-age=31536000"
        )

        self.send_header(
            "Content-Length",
            str(len(BODY))
        )

    def do_GET(self):
        if self.path == "/static/allowed.js":
            script = 'console.log("CSP TEST: Same-origin script executed successfully.");'.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(script)))
            self.end_headers()
            self.wfile.write(script)

        elif self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(BODY)

        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_security_headers()
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


def run_server():
    server_address = ("127.0.0.1", 8000)

    httpd = HTTPServer(
        server_address,
        SecurityHeaderLabHandler
    )

    print("[*] Day 16 HTTP Security Header Lab")
    print("[*] Server: http://127.0.0.1:8000")
    print("[*] Environment: Localhost / Authorized Testing")
    print("[*] Press CTRL+C to stop")

    httpd.serve_forever()


if __name__ == "__main__":
    run_server()