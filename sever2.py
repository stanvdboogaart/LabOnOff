import http.server
import socketserver

PORT = 80

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = """
        <html>
            <head><title>Simple HTTP Server</title></head>
            <body>
                <h1>Hello from Port 80!</h1>
                <p>This is a plain HTTP server.</p>
            </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        return  # Suppress logs

with socketserver.TCPServer(("", PORT), SimpleHandler) as httpd:
    print(f"Serving HTTP on port {PORT}...")
    httpd.serve_forever()
