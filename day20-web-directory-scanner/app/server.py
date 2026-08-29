from http.server import BaseHTTPRequestHandler, HTTPServer


HOST = "127.0.0.1"
PORT = 5000


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/": (
                200,
                "Day 20 local security lab\n"
                "Public application homepage.\n",
            ),
            "/admin": (
                403,
                "Forbidden\n",
            ),
            "/.env": (
                200,
                "APP_ENV=development\n"
                "DEBUG=true\n"
                "DATABASE_HOST=localhost\n",
            ),
            "/backup.sql": (
                200,
                "-- Intentional Day 20 lab artifact\n"
                "SELECT 'training-data';\n",
            ),
            "/missing": (
                404,
                "Not Found\n",
            ),
        }

        status, body = routes.get(
            self.path,
            (404, "Not Found\n"),
        )

        encoded = body.encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "text/plain; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(encoded)),
        )
        self.end_headers()

        self.wfile.write(encoded)

    def log_message(self, format, *args):
        print(f"[LAB] {self.address_string()} - {format % args}")


def main():
    server = HTTPServer((HOST, PORT), LabHandler)

    print("=" * 60)
    print("DAY 20 - LOCAL WEB DIRECTORY SECURITY LAB")
    print("=" * 60)
    print()
    print(f"Listening on: http://{HOST}:{PORT}")
    print("Authorized local training target only.")
    print()
    print("Intentional routes:")
    print("  /          -> 200")
    print("  /admin     -> 403")
    print("  /.env      -> 200  [SENSITIVE]")
    print("  /backup.sql -> 200  [SENSITIVE]")
    print("  /missing   -> 404")
    print()
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Lab server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
