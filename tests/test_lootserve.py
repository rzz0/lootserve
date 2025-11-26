import io
import os
import sys
import json
import errno
from pathlib import Path
from contextlib import redirect_stdout

import pytest

# Ensure repo root on path for `import lootserve`
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import lootserve as ls


# ---------- Minimal HTTP I/O harness (no real sockets) ----------

class FakeConn:
    def __init__(self, request_bytes: bytes):
        self.r = io.BytesIO(request_bytes)
        self.w = io.BytesIO()
    def makefile(self, mode, buffering=None):
        if 'r' in mode:
            return self.r
        return self.w
    def sendall(self, data):
        self.w.write(data)
    def close(self):
        pass


class DummyServer:
    pass


def run_raw(handler_cls, raw: bytes):
    conn = FakeConn(raw)
    handler_cls(conn, ('127.0.0.1', 12345), DummyServer())
    data = conn.w.getvalue()
    head, _, body = data.partition(b"\r\n\r\n")
    status_line = head.splitlines()[0].decode(errors='ignore') if head else ''
    headers = {}
    for line in head.splitlines()[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode().strip()] = v.decode().strip()
    return status_line, headers, body


def http_request(method: str, path: str, headers: dict = None, body: bytes = b'') -> bytes:
    headers = headers or {}
    lines = [f"{method} {path} HTTP/1.0\r\n"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode() + body


# ---------- Helpers / Style / Utilities ----------

def test_style_and_use_color(monkeypatch):
    monkeypatch.setattr(ls.sys.stdout, "isatty", lambda: True)
    assert ls.use_color(False) is True
    s = ls.Sty(True)
    _ = (s.B, s.D, s.CY, s.GR, s.YL, s.MG, s.BL)


def test_helpers_and_size():
    assert ls.cmd_quote('a b"c') == '"a b""c"'
    assert ls.ps_literal("a'b") == "'a''b'"
    assert ls.single_quote_literal("a'b\\c") == "a\\'b\\\\c"
    assert ls.human_size(999) == "999 B"
    assert "GB" in ls.human_size(5 * 1024**3)


def test_get_display_ip_variants(monkeypatch):
    assert ls.get_display_ip("10.1.2.3", "eth0") == "10.1.2.3"
    monkeypatch.setattr(ls, "_get_ip_by_iface_linux", lambda i: "10.9.9.9")
    assert ls.get_display_ip("0.0.0.0", "tun0") == "10.9.9.9"
    # Fallback to 127.0.0.1
    class DummySock:
        def connect(self, *a, **kw):
            raise OSError("no net")
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(ls.socket, 'socket', lambda *a, **kw: DummySock())
    monkeypatch.setattr(ls, "_get_ip_by_iface_linux", lambda i: "")
    assert ls.get_display_ip("0.0.0.0", "any") == "127.0.0.1"


def test_iface_linux_success_and_error(monkeypatch):
    import sys as _sys
    class FcntlOK:
        def ioctl(self, fd, req, ifreq):
            return bytes([0])*20 + bytes([1,2,3,4]) + bytes([0])*8
    monkeypatch.setitem(_sys.modules, 'fcntl', FcntlOK())
    assert ls._get_ip_by_iface_linux('eth0') == '1.2.3.4'
    class FcntlBad:
        def ioctl(self, *a, **kw):
            raise OSError('boom')
    monkeypatch.setitem(_sys.modules, 'fcntl', FcntlBad())
    assert ls._get_ip_by_iface_linux('eth0') == ''


def test_linux_windows_cmds_and_one_liner():
    url = "http://127.0.0.1/f.txt"
    assert "wget" in ls.one_liner("linux", url, "f.txt")
    assert "powershell" in ls.one_liner("windows", url, "f.txt")
    with pytest.raises(ValueError):
        ls.one_liner("macos", url, "f.txt")
    assert any("| bash" in c for c in ls.linux_cmds(url, "f.sh"))
    # Silent mode
    assert "wget -q" in ls.one_liner("linux", url, "f.txt", silent=True)
    assert "DownloadFile" in ls.one_liner("windows", url, "f.txt", silent=True)


def test_print_listing_and_blocks(tmp_path, capsys):
    (tmp_path/"a.txt").write_text("x")
    ls.print_listing(ls.Sty(False), "127.0.0.1", 1, str(tmp_path), client=None, full=True, recursive=False, silent=False)
    out = capsys.readouterr().out
    assert "Linux:" in out and "Windows:" in out
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="linux", compact=False, download_name="f", silent=False)
    out2 = capsys.readouterr().out
    assert "wget -O" in out2
    # Empty directory message
    empty = tmp_path/"empty"; empty.mkdir()
    ls.print_listing(ls.Sty(False), "127.0.0.1", 1, str(empty), client=None, full=False, recursive=False, silent=False)
    out3 = capsys.readouterr().out
    assert "No files in the current directory" in out3


def test_print_listing_compact_dual(tmp_path, capsys):
    (tmp_path/"a.txt").write_text("x")
    ls.print_listing(ls.Sty(False), "127.0.0.1", 1, str(tmp_path), client=None, full=False, recursive=False, silent=False)
    out = capsys.readouterr().out
    assert "Linux:" in out and "Windows:" in out and "a.txt" in out


def test_print_file_block_windows_full(capsys):
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="windows", compact=False, download_name="f", silent=False)
    out = capsys.readouterr().out
    assert "Windows (CMD/PowerShell):" in out and "iwr -UseBasicParsing" in out


def test_print_file_block_compact_branches(capsys):
    # Compact one-liners for both OS branches
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="linux", compact=True, download_name="f", silent=False)
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="windows", compact=True, download_name="f", silent=False)
    out = capsys.readouterr().out
    assert "wget -O" in out and "iwr -UseBasicParsing" in out


def test_list_regular_files_error_paths(tmp_path, monkeypatch):
    f = tmp_path/"f.txt"; f.write_text("x")
    bad = lambda p: (_ for _ in ()).throw(OSError('fail'))
    real = ls.os.path.getsize
    monkeypatch.setattr(ls.os.path, 'getsize', bad)
    files = ls.list_regular_files(str(tmp_path), recursive=False)
    monkeypatch.setattr(ls.os.path, 'getsize', real)
    assert files and files[0][1] == 0
    # Recursive
    sub = tmp_path/"s"; sub.mkdir(); (sub/"b.bin").write_bytes(b"1")
    monkeypatch.setattr(ls.os.path, 'getsize', bad)
    files_rec = ls.list_regular_files(str(tmp_path), recursive=True)
    monkeypatch.setattr(ls.os.path, 'getsize', real)
    assert any(name.endswith('b.bin') and size == 0 for name, size in files_rec)


# ---------- Handler via raw I/O (no real sockets) ----------

def test_get_upload_enabled(tmp_path):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path))
    status, headers, body = run_raw(Handler, http_request("GET", "/upload"))
    assert "200" in status and b"File Upload" in body


def test_get_upload_disabled(tmp_path):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=False, upload_dir=str(tmp_path))
    status, _, body = run_raw(Handler, http_request("GET", "/upload"))
    out = json.loads(body.decode()); assert "405" in status and out["status"] == "error"


def test_get_root_index(tmp_path):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path))
    (tmp_path/"index.txt").write_text("x")
    status, _, _ = run_raw(Handler, http_request("GET", "/"))
    assert "200" in status


def test_put_ok_and_errors(tmp_path, monkeypatch):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path), max_upload_mb=1)
    # OK
    data = b"DATA"; status, _, body = run_raw(Handler, http_request("PUT", "/d/x.bin", {"Content-Length": str(len(data))}, data))
    assert "201" in status and json.loads(body.decode())["status"] == "ok"
    assert (tmp_path/"d"/"x.bin").read_bytes() == data
    # Incomplete body
    status, _, body = run_raw(Handler, http_request("PUT", "/inc.bin", {"Content-Length": "10"}, b"abc"))
    assert "400" in status and json.loads(body.decode())["status"] == "error"
    # Missing length
    status, _, _ = run_raw(Handler, http_request("PUT", "/m.bin"))
    assert "411" in status
    # Invalid length
    status, _, _ = run_raw(Handler, http_request("PUT", "/m2.bin", {"Content-Length": "abc"}, b"x"))
    assert "400" in status
    # Too large
    status, _, _ = run_raw(Handler, http_request("PUT", "/big.bin", {"Content-Length": str(2*1024*1024)}, b"x"))
    assert "413" in status
    # Forbidden path
    status, _, _ = run_raw(Handler, http_request("PUT", "/../../evil.txt", {"Content-Length": "1"}, b"x"))
    assert "403" in status
    # Invalid trailing slash path
    status, _, _ = run_raw(Handler, http_request("PUT", "/dir/", {"Content-Length": "0"}, b""))
    assert "400" in status
    # Finalize failure
    real = os.replace; monkeypatch.setattr(os, 'replace', lambda a,b: (_ for _ in ()).throw(OSError('x')))
    status, _, _ = run_raw(Handler, http_request("PUT", "/z.bin", {"Content-Length": "1"}, b"X"))
    monkeypatch.setattr(os, 'replace', real)
    assert "500" in status


def test_post_multipart_and_variants(tmp_path, monkeypatch):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path), max_upload_mb=0)
    # multipart OK (max_upload_mb=0 means limit=0 -> we set fresh handler per case)
    Handler_ok = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path), max_upload_mb=1)
    bnd = "----b"; parts = [f"--{bnd}\r\n".encode(), b"Content-Disposition: form-data; name=\"file\"; filename=\"m.txt\"\r\n\r\n", b"HELLO", b"\r\n", f"--{bnd}--\r\n".encode()]
    body = b"".join(parts)
    status, _, rbody = run_raw(Handler_ok, http_request("POST", "/upload", {"Content-Type": f"multipart/form-data; boundary={bnd}", "Content-Length": str(len(body))}, body))
    assert "200" in status and json.loads(rbody.decode())["status"] == "ok"
    # Too large (with Handler having max_upload_mb=0)
    bnd2 = "----b2"; parts2 = [f"--{bnd2}\r\n".encode(), b"Content-Disposition: form-data; name=\"file\"; filename=\"m2.txt\"\r\n\r\n", b"X", b"\r\n", f"--{bnd2}--\r\n".encode()]
    body2 = b"".join(parts2)
    status, _, _ = run_raw(Handler, http_request("POST", "/upload", {"Content-Type": f"multipart/form-data; boundary={bnd2}", "Content-Length": str(len(body2))}, body2))
    assert "413" in status
    # Non-multipart
    status, _, _ = run_raw(Handler, http_request("POST", "/upload", {"Content-Type": "text/plain", "Content-Length": "0"}, b""))
    assert "400" in status
    # Simulate FieldStorage returning a list of items
    class Item:
        def __init__(self, name, filename, data):
            self.name, self.filename, self.file = name, filename, io.BytesIO(data)
    monkeypatch.setattr(ls.cgi, 'FieldStorage', lambda *a, **kw: [Item('file', 'z.txt', b'Z')])
    status, _, rbody2 = run_raw(Handler_ok, http_request("POST", "/upload", {"Content-Type": "multipart/form-data; boundary=x", "Content-Length": "0"}, b""))
    assert "200" in status and json.loads(rbody2.decode())["status"] == "ok"

    # Malformed multipart -> FieldStorage exception
    monkeypatch.setattr(ls.cgi, 'FieldStorage', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('bad')))
    status, _, body_bad = run_raw(Handler_ok, http_request("POST", "/upload", {"Content-Type": "multipart/form-data; boundary=x", "Content-Length": "0"}, b""))
    assert "400" in status and json.loads(body_bad.decode())["status"] == "error"


def test_post_raw_ok_and_errors(tmp_path, monkeypatch):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path), max_upload_mb=1)
    # OK
    status, _, body = run_raw(Handler, http_request("POST", "/raw", {"X-Filename": "r.txt", "Content-Length": "3"}, b"RAW"))
    assert "201" in status and json.loads(body.decode())["status"] == "ok"
    # Missing filename
    status, _, _ = run_raw(Handler, http_request("POST", "/raw", {"Content-Length": "1"}, b"X"))
    assert "400" in status
    # Missing length
    status, _, _ = run_raw(Handler, http_request("POST", "/raw", {"X-Filename": "x"}, b"X"))
    assert "411" in status
    # Invalid length
    status, _, _ = run_raw(Handler, http_request("POST", "/raw", {"X-Filename": "x", "Content-Length": "abc"}, b"X"))
    assert "400" in status
    # Too large
    Handler0 = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path), max_upload_mb=0)
    status, _, _ = run_raw(Handler0, http_request("POST", "/raw", {"X-Filename": "x", "Content-Length": "1"}, b"X"))
    assert "413" in status
    # Forbidden filename
    status, _, _ = run_raw(Handler, http_request("POST", "/raw?filename=../bad.txt", {"Content-Length": "1"}, b"X"))
    assert "403" in status
    # Finalize failure
    real = os.replace; monkeypatch.setattr(os, 'replace', lambda a,b: (_ for _ in ()).throw(OSError('x')))
    status, _, _ = run_raw(Handler, http_request("POST", "/raw", {"X-Filename": "f.bin", "Content-Length": "1"}, b"X"))
    monkeypatch.setattr(os, 'replace', real)
    assert "500" in status


def test_safe_join_exception(tmp_path, monkeypatch):
    Handler = ls.make_handler(verbose=False, logfile=None, upload_enabled=True, upload_dir=str(tmp_path))
    h = object.__new__(Handler)
    base = str(tmp_path)
    monkeypatch.setattr(ls.os.path, 'commonpath', lambda paths: (_ for _ in ()).throw(ValueError('x')))
    assert h._safe_join(base, 'x') is None


def test_make_handler_logging(tmp_path, monkeypatch):
    Handler = ls.make_handler(verbose=True, logfile=None)
    h = object.__new__(Handler); h.client_address=("1.2.3.4",1); h.log_date_time_string=lambda:"t"
    with redirect_stdout(io.StringIO()) as buf:
        h.log_message("GET %s %s", "/", 200)
    assert "1.2.3.4" in buf.getvalue()
    # logfile fallback
    import builtins
    monkeypatch.setattr(builtins, 'open', lambda *a, **kw: (_ for _ in ()).throw(OSError('fail')))
    Handler2 = ls.make_handler(verbose=False, logfile=str(tmp_path/"x.log"))
    h2 = object.__new__(Handler2); h2.client_address=("9.9.9.9",1); h2.log_date_time_string=lambda:"t2"
    with redirect_stdout(io.StringIO()) as buf2:
        h2.log_message("Z")
    assert "9.9.9.9" in buf2.getvalue()


# ---------- Server selection and main() ----------

def test_start_server_port_fallback(monkeypatch):
    attempts = []
    class FakeServer:
        def __init__(self, addr, handler):
            host, port = addr; attempts.append(port)
            if port in (8000, 8080):
                e = OSError(); e.errno = errno.EADDRINUSE; raise e
            self.server_address = (host, port)
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeServer)
    from contextlib import redirect_stdout
    import io as _io
    buf=_io.StringIO()
    with redirect_stdout(buf):
        server, port = ls.start_server_with_port_selection("127.0.0.1", 8000, object, ls.Sty(False))
    assert port not in (8000, 8080)
    txt=buf.getvalue()
    assert "already in use" in txt


def test_start_server_dynamic_when_all_busy(monkeypatch):
    class FakeAllBusy:
        def __init__(self, addr, handler):
            host, port = addr
            e = OSError(); e.errno = errno.EADDRINUSE
            if port == 0:
                self.server_address = (host, 55555)
            else:
                raise e
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeAllBusy)
    from contextlib import redirect_stdout
    import io as _io
    buf=_io.StringIO()
    with redirect_stdout(buf):
        server, port = ls.start_server_with_port_selection("127.0.0.1", None, object, ls.Sty(False))
    assert port == 55555
    assert "Using dynamic port" in buf.getvalue()


def test_start_server_permission_denied_then_ok(monkeypatch):
    calls = []
    class FakeServer:
        def __init__(self, addr, handler):
            host, port = addr; calls.append(port)
            e = OSError(); e.errno = errno.EACCES
            if port == 80:
                raise e
            self.server_address = (host, port)
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeServer)
    from contextlib import redirect_stdout
    import io as _io
    buf=_io.StringIO()
    with redirect_stdout(buf):
        server, port = ls.start_server_with_port_selection("127.0.0.1", 80, object, ls.Sty(False))
    txt = buf.getvalue()
    assert "Permission denied" in txt and port != 80


def test_main_basic_and_uploads(tmp_path, monkeypatch, capsys):
    # Fake server that exits immediately
    class FakeServer:
        def __init__(self, addr, handler):
            self.server_address = (addr[0], 55555 if addr[1]==0 else addr[1])
        def serve_forever(self): raise KeyboardInterrupt
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeServer)
    monkeypatch.setattr(ls, 'get_display_ip', lambda h,i: '127.0.0.1')
    old_argv = sys.argv[:]
    try:
        # basic
        sys.argv = ["lootserve.py", "-d", str(tmp_path)]
        ls.main()
        out = capsys.readouterr().out
        assert "Server" in out and "URL:" in out
        # uploads + logs
        (tmp_path/"uploads").mkdir()
        sys.argv = ["lootserve.py", "-d", str(tmp_path), "--upload", "--upload-dir", str(tmp_path/"uploads"), "--max-upload-mb", "1", "-v", "--logfile", str(tmp_path/"a.log"), "-p", "0"]
        ls.main()
        out2 = capsys.readouterr().out
        assert "Uploads:" in out2 and "limit: 1 MB" in out2
    finally:
        sys.argv = old_argv


def test_main_invalid_dir(monkeypatch, tmp_path, capsys):
    class FakeServer:
        def __init__(self, addr, handler):
            self.server_address = (addr[0], 55555 if addr[1]==0 else addr[1])
        def serve_forever(self): raise KeyboardInterrupt
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeServer)
    old_argv = sys.argv[:]
    try:
        sys.argv = ["lootserve.py", "-d", str(tmp_path/"does_not_exist")]
        with pytest.raises(SystemExit) as ex:
            ls.main()
        assert ex.value.code == 1
    finally:
        sys.argv = old_argv


def test_main_logfile_only(tmp_path, monkeypatch, capsys):
    class FakeServer:
        def __init__(self, addr, handler):
            self.server_address=(addr[0], 55555 if addr[1]==0 else addr[1])
        def serve_forever(self): raise KeyboardInterrupt
        def server_close(self): pass
    monkeypatch.setattr(ls, 'ReusableThreadingHTTPServer', FakeServer)
    monkeypatch.setattr(ls, 'get_display_ip', lambda h,i: '127.0.0.1')
    old_argv = sys.argv[:]
    try:
        sys.argv = ["lootserve.py", "-d", str(tmp_path), "--logfile", str(tmp_path/"acc.log"), "-p", "0"]
        ls.main()
        out = capsys.readouterr().out
        assert "Access log →" in out
    finally:
        sys.argv = old_argv


def test_snippets_richer():
    wc = "\n".join(ls.win_cmds("http://h/f", "f"))
    assert "certutil -urlcache" in wc and "Start-BitsTransfer" in wc and "bitsadmin" in wc
    lc = "\n".join(ls.linux_cmds("http://h/f", "f"))
    assert "aria2c" in lc and "axel" in lc and "perl -MLWP::Simple" in lc


def test_compact_dual_direct(capsys):
    ls.print_file_block_compact_dual(ls.Sty(False), "http://h/file", "file", 1234, "file", silent=False)
    out = capsys.readouterr().out
    assert "Linux:" in out and "Windows:" in out


def test_silent_mode(tmp_path, capsys):
    (tmp_path/"test.txt").write_text("x")
    # Test silent mode in listing
    ls.print_listing(ls.Sty(False), "127.0.0.1", 1, str(tmp_path), client=None, full=False, recursive=False, silent=True)
    out = capsys.readouterr().out
    assert "wget -q" in out and "DownloadFile" in out
    # Test silent mode with specific client
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="linux", compact=True, download_name="f", silent=True)
    out2 = capsys.readouterr().out
    assert "wget -q" in out2
    ls.print_file_block(ls.Sty(False), "http://h/f", "f", 1000, client="windows", compact=True, download_name="f", silent=True)
    out3 = capsys.readouterr().out
    assert "DownloadFile" in out3


def test_version_and_module_meta(monkeypatch, capsys):
    assert isinstance(ls.__version__, str)
    old_argv = sys.argv[:]
    try:
        sys.argv = ["lootserve.py", "-V"]
        with pytest.raises(SystemExit) as ex:
            ls.main()
        assert ex.value.code == 0
    finally:
        sys.argv = old_argv

print('wrote file')
