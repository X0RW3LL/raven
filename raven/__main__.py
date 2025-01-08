#!/usr/bin/env python3

import io
import os
import re
import sys
import html
import errno
import urllib
import argparse
import http.server
import socketserver
from http import HTTPStatus
from datetime import datetime
from ipaddress import (ip_network, ip_address)


# Instantiate our FileUploadHandler class
class FileUploadHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Overwrite default versions to minimize fingerprinting
        self.server_version = "nginx"
        self.sys_version = ""
        self.upload_dir = kwargs.pop('upload_dir', None)
        self.allowed_ip = kwargs.pop('allowed_ip', None)
        self.organize_uploads = kwargs.pop('organize_uploads', False)
        super().__init__(*args, **kwargs)

    # Define our handler method for restricting access by client ip
    def restrict_access(self):
        if not self.allowed_ip:
            # Access is permitted by default
            return True  
        
        # Obtain the client ip
        client_ip = ip_address(self.client_address[0])

        # Cycle through each entry in allowed_ips for permitted access
        allowed_ips = self.allowed_ip.split(',')
        for ip in allowed_ips:
            ip = ip.strip()     
            # Check if the entry is in CIDR notation
            if '/' in ip:
                try:
                    network = ip_network(ip, strict=False)
                    if client_ip in network:
                        return True
                except ValueError:
                    pass
            elif client_ip == ip_address(ip):
                return True
            
        # The client ip is not permitted access to the handler
        # Respond back to the client with a 403 status code
        self.send_response(403)
        self.end_headers()
        return False

    # Below is a slightly modified version of
    # http.server.SimpleTCPRequestHandler.list_directory
    # The method has been modified to show the upload form
    # above the directory listing, as well as a change in how
    # link names are provided; we need the correct paths (using fullname)
    # to serve files requested via browsers
    # Additionally, we're not using the original method so that we
    # are able to respond with the correct Content-Length header
    # Each individual change is prefixed with a NOTE
    def list_dirs(self):
        # Copyright (c) 2001 Python Software Foundation; All Rights Reserved
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """

        # NOTE: overriding the original implementation to
        # append an upload form above the directory listing
        upload_form = """<h1>File upload</h1>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
<br>
<hr>
"""

        try:
            # NOTE: quick and dirty override to the original implementation
            # to skip the missing favicon.ico
            if 'favicon.ico' in self.translate_path(self.path):
                try:
                    self.send_error(
                        HTTPStatus.NOT_FOUND,
                        "Resource not found")
                # Worst case scenario, we send a 404 twice
                except BrokenPipeError:
                    self.send_error(
                        HTTPStatus.NOT_FOUND,
                        "Resource not found")
                finally:
                    return None
            # NOTE: use http.server.SimpleHTTPRequestHandler.translate_path
            # since we already have access to it
            dir_list = os.listdir(self.translate_path(self.path))
        # NOTE: add ValueError to exception list to avoid
        # processing NULL characters
        except (OSError, ValueError):
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "Resource not found")
            return None
        dir_list.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = f'Directory listing for {displaypath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{enc}">')
        r.append(f'<title>Raven File Upload/Download</title>\n</head>')
        r.append(f'<body>\n{upload_form}<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in dir_list:
            fullname = os.path.join(self.path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            # NOTE: overriding the original implementation to use
            # fullname instead of linkname so files are served
            # correctly to browser clients
            r.append('<li><a href="%s">%s</a></li>'
                    % (urllib.parse.quote(fullname,
                                          errors='surrogatepass'),
                       html.escape(displayname, quote=False)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    # Serve requested file
    def serve_file(self, canon_name, basename):
        with open(canon_name, 'rb') as f:
            content = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition',
                             'attachment; filename={}'.format(basename))
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    # Define our GET handler method
    def do_GET(self):
        BASENAME = os.path.basename(self.path)
        CANON_FILENAME = self.translate_path(self.path)
        if not os.path.isfile(CANON_FILENAME):
            # Check if we are restricting access
            if not self.restrict_access():
                return

            try:
                self.wfile.write(self.list_dirs().read())
            except AttributeError:
                pass
        else:
            self.serve_file(CANON_FILENAME, BASENAME)

    # Define our POST handler method
    def do_POST(self):
        # Check if we are restricting access
        if not self.restrict_access():
            return

        # Inspect incoming multipart/form-data content
        content_type = self.headers['Content-Type']
        if content_type.startswith('multipart/form-data'):
            try:
                # Extract and parse multipart/form-data content
                content_length = int(self.headers['Content-Length'])
                form_data = self.rfile.read(content_length)

                # Extract the boundary from the content type header
                boundary = content_type.split('; ')[1].split('=')[1]

                # Split the form data using the boundary
                parts = form_data.split(b'--' + boundary.encode())

                for part in parts:
                    if b'filename="' in part:
                        # Extract the filename from Content-Disposition header
                        headers, data = part.split(b'\r\n\r\n', 1)
                        content_disposition = headers.decode()
                        filename = re.search(r'filename="(.+)"', content_disposition).group(1)

                        # Sanitize the filename based on our requirements
                        filename = sanitize_filename(filename)

                        # Organize uploads into subfolders by client IP otherwise use the default
                        if self.organize_uploads and self.client_address:
                            client_ip = self.client_address[0]
                            upload_dir = os.path.join(self.upload_dir, client_ip)
                            os.makedirs(upload_dir, exist_ok=True)
                            file_path = os.path.join(upload_dir, filename)
                        else:
                            upload_dir = self.upload_dir
                            file_path = os.path.join(upload_dir, filename)

                        # Generate a unique filename in case the file already exists
                        file_path = prevent_clobber(upload_dir, filename)

                        # Save the uploaded file in binary mode so we don't corrupt any content
                        with open(file_path, 'wb') as f:
                            f.write(data[:-2])

                        # Respond back to the client with a 200 status code
                        self.send_response(200)
                        self.end_headers()

                        # Send an HTML response to the client for redirection
                        self.wfile.write(b"""<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="refresh" content="3;url=/" charset="utf-8">
<title>Redirecting...</title>
</head>
<body>
<p>File uploaded successfully. Redirecting in 3 seconds...</p>
</body>
</html>
""")

                        # Print the path where the uploaded file was saved to the terminal
                        now = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
                        print(f"{self.client_address[0]} - - [{now}] \"File saved {file_path}\"")
                        return
            except Exception as e:
                print(f"Error processing the uploaded file: {str(e)}")

        # Something bad happened if we get to this point
        # Error details are provided by http.server on the terminal
        # Respond back to the client with a 400 status code
        self.send_response(400)
        self.end_headers()


# Normalizes the filename, then remove any characters that are not letters, numbers, underscores, dots, or hyphens
def sanitize_filename(filename):
    normalized = os.path.normpath(filename)
    sanitized = re.sub(r'[^\w.-]', '_', normalized)
    return sanitized


# Appends a file name with an incrementing number if it happens to exist already
def prevent_clobber(upload_dir, filename):
    file_path = os.path.join(upload_dir, filename)
    counter = 1
    # Keep iterating until a unique filename is found
    while os.path.exists(file_path):
        base_name, file_extension = os.path.splitext(filename)
        new_filename = f"{base_name}_{counter}{file_extension}"
        file_path = os.path.join(upload_dir, new_filename)
        counter += 1

    return file_path


# Generates the epilog content for argparse, providing usage examples
def generate_epilog():
    examples = [
        "examples:",
        "  Start the HTTP server on all available network interfaces, listening on port 443",
        "  raven 0.0.0.0 443\n",
        "  Bind the HTTP server to a specific address (192.168.0.12), listening on port 443, and restrict access to 192.168.0.4",
        "  raven 192.168.0.12 443 --allowed-ip 192.168.0.4\n",
        "  Bind the HTTP server to a specific address (192.168.0.12), listening on port 443, restrict access to 192.168.0.4, and save uploaded files to /tmp",
        "  raven 192.168.0.12 443 --allowed-ip 192.168.0.4 --upload-dir /tmp\n",
        "  Bind the HTTP server to a specific address (192.168.0.12), listening on port 443, restrict access to 192.168.0.4, and save uploaded files to /tmp organized by remote client IP",
        "  raven 192.168.0.12 443 --allowed-ip 192.168.0.4 --upload-dir /tmp --organize-uploads",
    ]
    return "\n".join(examples)


def main():
    # Build the parser
    parser = argparse.ArgumentParser(
        description="A lightweight file upload service used for penetration testing and incident response.",
        usage="raven [lhost] [lport] [--allowed-ip <allowed_client_ip>] [--upload-dir <upload_directory>] [--organize-uploads]",
        epilog=generate_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Configure our arguments
    parser.add_argument("lhost", nargs="?", default="0.0.0.0", help="The IP address for our HTTP handler to listen on (default: listen on all interfaces)")
    parser.add_argument("lport", nargs="?", type=int, default=8080, help="The port for our HTTP handler to listen on (default: 8080)")
    parser.add_argument("--allowed-ip", help="Restrict access to our HTTP handler by IP address (optional)")
    parser.add_argument("--upload-dir", default=os.getcwd(), help="Designate the directory to save uploaded files to (default: current working directory)")
    parser.add_argument("--organize-uploads", action="store_true", help="Organize file uploads into subfolders by remote client IP")

    # Parse the command-line arguments
    args = parser.parse_args()


    # Initializing configuration variables
    host = args.lhost
    port = args.lport
    allowed_ip = args.allowed_ip
    upload_dir = args.upload_dir
    organize_uploads = args.organize_uploads
    server = None

    try:
        # Check if the specified upload folder exists, if not try to create it
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        # set SO_REUSEADDR (See man:socket(7))
        socketserver.TCPServer.allow_reuse_address = True

        # Create an HTTP server instance with our custom request handling
        with socketserver.TCPServer((host, port), lambda *args, **kwargs: FileUploadHandler(*args, **kwargs, upload_dir=upload_dir, allowed_ip=allowed_ip, organize_uploads=organize_uploads)) as server:
            # Print our handler details to the terminal
            print(f"[*] Serving HTTP on {host} port {port} (http://{host}:{port}/)")

            # Print additional details to the terminal
            if allowed_ip:
                print(f"[*] Listener access is restricted to {allowed_ip}")
            else:
                print(f"[*] Listener access is unrestricted")

            if organize_uploads:
                print(f"[*] Uploads will be organized by client IP in {upload_dir}")
            else:
                print(f"[*] Uploads will be saved in {upload_dir}")

            # Start the HTTP server and keep it running until we stop it
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
    except OSError as ose:
        if ose.errno == errno.EADDRNOTAVAIL:
            print(f"[!] The IP address '{host}' does not appear to be available on this system")
            exit(ose.errno)
        else:
            print(f"[!] {str(ose)}")
            exit(ose.errno)
    except Exception as ex:
        print(f"[!] {str(ex)}")
        exit(ose.errno)
    finally:
        if server:
            server.server_close()


if __name__ == '__main__':
    main()
