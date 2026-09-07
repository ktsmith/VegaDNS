"""Run application HTTP regressions on loopback with a disposable SQLite DB.
Usage: python tests/http_security.py /path/to/php [PHP options, e.g. -d extension=pdo_sqlite]
The harness explicitly forwards Secure cookies over loopback HTTP; TLS and the
production webserver configuration still require deployment acceptance testing.
"""
import http.client
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
PHP = sys.argv[1:] or ["php"]
checks = 0

def check(ok, message):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(message)

for backend in ("files", "mysql"):
    with tempfile.TemporaryDirectory(prefix="vegadns-http-") as tmp:
        env = dict(os.environ, VEGADNS_HTTP_TEST_DB=str(Path(tmp)/"test.db"),
                   VEGADNS_HTTP_TEST_SESSIONS=tmp, VEGADNS_HTTP_TEST_BACKEND=backend)
        subprocess.run(PHP + [str(ROOT/"tests/fixture.php")], env=env, check=True, capture_output=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with open(Path(tmp)/"server.log", "w+") as log:
            server = subprocess.Popen(PHP + ["-S", f"127.0.0.1:{port}", str(ROOT/"tests/router.php")],
                                      cwd=ROOT, env=env, stdout=log, stderr=log)
            cookie = "VDNSSessid=attacker-fixed-id"
            def request(params=None, post=None, headers=None):
                global cookie
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                target = "/index.php" + ("?"+urllib.parse.urlencode(params) if params else "")
                h = {"Cookie": cookie}
                if headers:
                    h.update(headers)
                body = None
                if post is not None:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                    body = urllib.parse.urlencode(post)
                conn.request("POST" if post is not None else "GET", target, body, h)
                response = conn.getresponse()
                data = response.read().decode("utf-8")
                result = (response.status, dict(response.getheaders()), data)
                if response.getheader("Set-Cookie"):
                    cookie = response.getheader("Set-Cookie").split(";", 1)[0]
                conn.close()
                return result
            def csrf(body):
                return re.search(r'name="csrf" value="([a-f0-9]{64})"', body).group(1)
            try:
                for attempt in range(100):
                    try:
                        first = request()
                        break
                    except (ConnectionError, OSError):
                        if server.poll() is not None:
                            raise RuntimeError("Test server failed to start")
                        time.sleep(.05)
                else:
                    raise RuntimeError("Server startup timed out")
                status, headers, body = first
                check(status == 200 and "Sign in" in body, "Anonymous sign-in page")
                check("attacker-fixed-id" not in cookie, "Strict mode rejects supplied unknown session")
                flags = headers["Set-Cookie"].lower()
                check(all(x in flags for x in ("secure", "httponly", "samesite=lax")), "Cookie flags")
                anon = cookie
                check(request({"state":"login", "password":"secret"})[0] == 400, "Password in GET rejected")
                check(request({"VDNSSessid":"fixed"})[0] == 400, "URL session rejected")
                check(request(post={"state":"login","email":"alice@example.test","password":"test-password-123"})[0] == 403, "Login CSRF required")
                result = request(post={"state":"login","email":"alice@example.test","password":"test-password-123","csrf":csrf(body)})
                check(result[0] == 303 and cookie != anon, "Successful login rotates session and redirects")
                status, headers, body = request({"state":"logged_in","mode":"domains"})
                check(status == 200 and "alice.test" in body and "bob.test" not in body, "Domain list isolated")
                token = csrf(body)
                base = {"state":"logged_in","mode":"records","domain_id":"1"}
                status, headers, body = request(base)
                check(status == 200 and "&lt;script&gt;" in body and "<script>" not in body, "Stored record XSS escaped")
                check(request(base | {"record_mode":"delete_now","record_id":"2","csrf":token})[0] == 405, "GET deletion rejected")
                check(request(post=base | {"record_mode":"delete_now","record_id":"4","csrf":token})[0] == 404, "Cross-tenant record deletion rejected")
                check(request(base | {"domain_id":"2"})[0] == 404, "Cross-tenant domain rejected")
                check(request(base | {"record_id":"1 OR 1=1"})[0] == 400, "Record ID SQL injection rejected")
                check(request(base | {"sortfield":"host; DROP TABLE accounts"})[0] == 400, "Sort injection rejected")
                check(request(post=base | {"record_mode":"delete_now","record_id":"2","csrf":"bad"})[0] == 403, "Mutation CSRF rejected")
                check(request(post=base | {"record_mode":"delete_now","record_id":"2","csrf":token},headers={"Origin":"https://attacker.test"})[0] == 403, "Cross-origin form rejected")
                check(request(post={"state":"logged_in","mode":"domains","domain_mode":"import_domains_now","domains":"example.test","hostname":"127.0.0.1","csrf":token})[0] == 403, "Tenant transfer rejected before network")
                check(request({"state":"get_data"})[0] == 403, "Export needs service credential")
                check(request({"state":"get_data"},headers={"Authorization":"Bearer "+"x"*64})[0] == 200, "Bearer export accepted")
                check(request(post={"state":"end","csrf":token})[0] == 303, "POST logout")
                check("Sign in" in request(base)[2], "Logged-out session loses access")
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                server.terminate()
                server.wait(timeout=10)
print(f"PASS: {checks} HTTP checks across file and database session handlers")
