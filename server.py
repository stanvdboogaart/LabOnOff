import os
import http.server
import ssl
import socket
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
    print("Generating self-signed cert")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyHTTPS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(
        key, hashes.SHA256())

    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        hostname = self.headers.get("Host", "localhost").split(":")[0]
        # new_url = f"https://{hostname}:4443{self.path}"
        new_url = "https://"+ hostname +":4443" + self.path
        self.send_header("Location", new_url)
        self.end_headers()
        # message = f"Please use HTTPS instead: {new_url}"
        message = "Please use HTTPS instead: " + new_url
        self.wfile.write(message.encode("utf-8"))

    def log_message(self, format, *args):
        return 

def start_http_redirect_server():
    try:
        httpd = http.server.HTTPServer(("0.0.0.0", 80), RedirectHandler)
        print("HTTP redirect server running on http://0.0.0.0:80")
        httpd.serve_forever()
    except PermissionError:
        print("You need admin/root privileges to bind to port 80.")

threading.Thread(target=start_http_redirect_server, daemon=True).start()


port = 4443
class CustomHTTPSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = "<html><body><h1>website</h1></body></html>"
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        return

httpd = http.server.HTTPServer(('0.0.0.0', port), CustomHTTPSHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
# print(f"HTTPS server running on https://{local_ip}:{port} (or https://localhost:{port})")
print("HTTPS server running on https://"+ local_ip +":" + port "(or https://localhost:" + port)

httpd.serve_forever()