import os
import sys
import socket
import threading
import mimetypes
import email.utils
import time
from datetime import datetime
from urllib.parse import unquote, urlsplit

# --------------------------- Configuration --------------------------- #
SERVER_NAME      = "COMP2322/1.0"
DEFAULT_PORT     = 8080
DEFAULT_DOCROOT  = "www"
MAX_REQUEST_SIZE = 32 * 1024  
LOG_FILE         = "server.log"

log_lock = threading.Lock()    

# ------------------------------ Logging ------------------------------ #

def log_request(addr, method, target, code, size):
    """Append one Common Log Format line to *server.log*."""
    now  = datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S +0000')
    line = f"{addr[0]} - - [{now}] \"{method} {target} HTTP/1.1\" {code} {size}\n"
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)

# ---------------------------- HTTP helpers --------------------------- #

STATUS_MESSAGES = {
    200: "OK",
    304: "Not Modified",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    415: "Unsupported Media Type",
}

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

def parse_http_date(val: str):
    try:
        parsed_time = email.utils.parsedate_to_datetime(val)
        if parsed_time:
            return int(parsed_time.timestamp())
        day, dd, mon, yyyy, hhmmss, gmt = val.split()
        if gmt.upper() != "GMT":
            return None
        dt = datetime(int(yyyy), MONTHS.get(mon, 0), int(dd), *map(int, hhmmss.split(':')))
        return int(dt.replace(tzinfo=datetime.utcnow().astimezone().tzinfo).timestamp())
    except Exception:
        return None

def fmt_http_date(ts: int | None = None):
    return email.utils.formatdate(ts if ts is not None else time.time(), usegmt=True)

# -------------------------- Response helpers ------------------------- #

def send_simple(client: socket.socket, code: int, body: bytes, mime: str | None,
                last_mod_ts: int | None, keep_alive: bool, method: str):
    head = [
        f"HTTP/1.1 {code} {STATUS_MESSAGES[code]}",
        f"Date: {fmt_http_date()}",
        f"Server: {SERVER_NAME}",
        f"Connection: {'keep-alive' if keep_alive else 'close'}",
    ]
    if code not in (304, ):
        head.append(f"Content-Length: {len(body)}")
        head.append(f"Content-Type: {mime or 'application/octet-stream'}")
    if last_mod_ts is not None:
        head.append(f"Last-Modified: {fmt_http_date(last_mod_ts)}")

    packet = ("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1")
    
   
    print("\n[Response Headers]")
    for header in head:
        print(f"  {header}")
    
    if method == "GET" and code not in (304,):
        packet += body
        print(f"  [Body] {len(body)} bytes")
    else:
        print("  [Body] None")
        
    try:
        client.sendall(packet)
    except BrokenPipeError:
        pass

def send_error(client: socket.socket, code: int, keep_alive: bool, method: str, addr=None, path=None):
    payload = b"" if method == "HEAD" else f"<h1>{code} {STATUS_MESSAGES[code]}</h1>".encode()
    send_simple(client, code, payload, "text/html", None, keep_alive, method)
    # Log error responses
    if addr and path:
        log_request(addr, method, path, code, len(payload))

# -------------------------- Request handling ------------------------- #

def respond(client: socket.socket, addr, docroot: str):
    print(f"[Connection] New connection from {addr[0]}:{addr[1]}")
    client.settimeout(10)
    buf = b""
    while True:
        try:
            chunk = client.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" not in buf and len(buf) < MAX_REQUEST_SIZE:
            continue
        try:
            header_blob, buf = buf.split(b"\r\n\r\n", 1)
            lines = header_blob.decode("iso-8859-1").split("\r\n")
            method, raw_target, version = lines[0].split()
            
            print(f"\n[Request] {method} {raw_target} {version}")
            print(f"[Client] {addr[0]}:{addr[1]}")
        except Exception:
            print(f"[Error] Bad request from {addr[0]}:{addr[1]}")
            send_error(client, 400, False, "GET", addr, "Bad Request")
            break

        headers = {}
        for h in lines[1:]:
            if ':' not in h:
                print(f"[Error] Invalid header: {h}")
                send_error(client, 400, False, method, addr, raw_target)
                return
            k, v = h.split(':', 1)
            headers[k.lower()] = v.lstrip()
        
        if 'host' in headers:
            print(f"[Header] Host: {headers['host']}")
        if 'user-agent' in headers:
            print(f"[Header] User-Agent: {headers['user-agent']}")
        if 'if-modified-since' in headers:
            print(f"[Header] If-Modified-Since: {headers['if-modified-since']}")
        if 'connection' in headers:
            print(f"[Header] Connection: {headers['connection']}")

        # keep‑alive negotiation
        keep_alive = True
        if version == "HTTP/1.0":
            keep_alive = headers.get("connection", "").lower() == "keep-alive"
        elif headers.get("connection", "").lower() == "close":
            keep_alive = False

        if method not in ("GET", "HEAD"):
            print(f"[Error] Unsupported method: {method}")
            send_error(client, 400, keep_alive, method, addr, raw_target)
            continue

        path = unquote(urlsplit(raw_target).path)
        if ".." in path:
            print(f"[Error] Path traversal attempt: {path}")
            send_error(client, 403, keep_alive, method, addr, path)
            continue

        if path.endswith('/'):
            path += 'index.html'
        fs_path = os.path.normpath(os.path.join(docroot, path.lstrip('/')))
        print(f"[Path] {path} -> {fs_path}")

        abs_root = os.path.abspath(docroot)
        abs_path = os.path.abspath(fs_path)
        if os.path.commonpath([abs_path, abs_root]) != abs_root:
            print(f"[Error] Path outside docroot: {abs_path}")
            send_error(client, 403, keep_alive, method, addr, path)
            continue

        if not os.path.exists(fs_path):
            print(f"[Error] File not found: {fs_path}")
            send_error(client, 404, keep_alive, method, addr, path)
            continue

        mime, _ = mimetypes.guess_type(fs_path)
        if mime is None:
            print(f"[Error] Unknown MIME type for: {fs_path}")
            send_error(client, 415, keep_alive, method, addr, path)
            continue
        print(f"[MIME] {mime}")

        last_mod = int(os.path.getmtime(fs_path))
        ims_hdr  = headers.get('if-modified-since')
        if ims_hdr:
            ims_val = parse_http_date(ims_hdr)
            if ims_val is not None and last_mod <= ims_val:
                print(f"[Response] 304 Not Modified (Last-Modified: {fmt_http_date(last_mod)})")
                send_simple(client, 304, b"", mime, last_mod, keep_alive, method)
                log_request(addr, method, path, 304, 0)
                if not keep_alive:
                    break
                continue

        try:
            with open(fs_path, 'rb') as fh:
                body = fh.read() if method == 'GET' else b""
        except PermissionError:
            print(f"[Error] Permission denied: {fs_path}")
            send_error(client, 403, keep_alive, method, addr, path)
            continue

        print(f"[Response] 200 OK ({len(body)} bytes, Last-Modified: {fmt_http_date(last_mod)})")
        send_simple(client, 200, body, mime, last_mod, keep_alive, method)
        log_request(addr, method, path, 200, len(body))
        if not keep_alive:
            break
    client.close()
    print(f"[Connection] Closed for {addr[0]}:{addr[1]}")

# ------------------------------ Server ------------------------------- #

def run_server(port: int, docroot: str):
    if not os.path.isdir(docroot):
        print(f"[fatal] DOC_ROOT '{docroot}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    original_port = port
    max_attempts = 10  
    
    for attempt in range(max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind(('0.0.0.0', port)) 
                break  
        except OSError:
            print(f"[warning] Port {port} is already in use")
            port += 1
            if attempt == max_attempts - 1:
                print(f"[fatal] Could not find an available port after {max_attempts} attempts")
                sys.exit(1)
    
    if port != original_port:
        print(f"[info] Port changed from {original_port} to {port}")
    
  
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"# Server started at {datetime.now()} on port {port}\n")
    

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
        s.close()
    except:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))  
        s.listen()
        print(f"[info] Serving {docroot} on port {port} — Ctrl+C to stop…")
        print(f"[info] Local access URL: http://localhost:{port}/")
        print(f"[info] Network access URL: http://{local_ip}:{port}/")
        try:
            while True:
                client, addr = s.accept()
                threading.Thread(target=respond,
                                 args=(client, addr, docroot),
                                 daemon=True).start()
        except KeyboardInterrupt:
            print("\n[info] Server shutting down.")

# ----------------------------- Entrypoint ---------------------------- #

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    root = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DOCROOT
    mimetypes.init()
    run_server(p, root)
