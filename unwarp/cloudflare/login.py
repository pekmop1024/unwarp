"""Interactive Cloudflare One sign-in for a single unwarp enrollment."""

import base64
import binascii
import getpass
import json
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


MAX_CALLBACK = 16384
FINISH_PAGE = b"""<!doctype html><meta charset=utf-8><title>Unwarp sign-in</title>
<p id="status">Completing your Cloudflare sign-in...</p>
<script>
async function finish() {
  const callback = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  const response = await fetch(location.pathname, {
    method: 'POST', body: decodeURIComponent(callback), cache: 'no-store'
  });
  if (!response.ok) throw new Error();
  document.querySelector('#status').textContent = 'Sign-in received. Return to unwarp.';
}
finish().catch(() => {
  document.querySelector('#status').textContent = 'Sign-in was not accepted. Return to unwarp.';
});
</script>"""


def team_host(team):
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', team):
        raise ValueError('expected a Cloudflare team name such as my-team')
    return f'{team}.cloudflareaccess.com'


def enrollment_url(team, supplied):
    host = team_host(team)
    if supplied is None:
        return f'https://{host}/warp'
    uri = urlsplit(supplied)
    if (uri.scheme != 'https' or uri.netloc.lower() != host or uri.fragment
            or not uri.path.startswith('/') or any(ord(c) <= 32 for c in supplied)):
        raise ValueError('the enrollment URL must be an HTTPS link issued by the selected team')
    return supplied


def read_assertion(callback, team):
    """Check the intended handoff. The device API verifies the assertion signature and enrollment policy."""
    if len(callback) > MAX_CALLBACK or any(ord(char) <= 32 for char in callback):
        raise ValueError('invalid Cloudflare enrollment callback')
    uri = urlsplit(callback)
    host = team_host(team)
    if (uri.scheme != 'com.cloudflare.warp' or uri.netloc.lower() != host
            or uri.path != '/auth' or uri.fragment):
        raise ValueError('expected a Cloudflare registration callback for the selected team')
    values = parse_qs(uri.query, keep_blank_values=True).get('token', [])
    if len(values) != 1 or not re.fullmatch(r'[\w-]+\.[\w-]+\.[\w-]+', values[0], re.ASCII):
        raise ValueError('expected one Cloudflare enrollment assertion')
    payload = values[0].split('.')[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        account = uuid.UUID(claims['account_id']).hex
        expires = claims['exp']
        if (isinstance(expires, bool) or not isinstance(expires, (float, int))
                or not math.isfinite(expires) or expires <= time.time()):
            raise ValueError
        issuer = f'https://{host}'
        if claims.get('warp', True) is not True or claims.get('iss', issuer).rstrip('/') != issuer:
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, binascii.Error):
        raise ValueError('invalid or expired enrollment assertion for this team; start a fresh sign-in') from None
    return values[0], account


class LoginReceiver(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Requests carry a one-time capability.

    def reply(self, status, body=b''):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def matches(self, path):
        return self.path == path and self.headers.get('Host') == self.server.authority

    def do_GET(self):
        if self.matches(self.server.start_path):
            self.server.started = True
            self.reply(200, b'<!doctype html><meta charset=utf-8><title>Unwarp sign-in</title>'
                            b'<p>Complete your Cloudflare sign-in in the Firefox window opened by unwarp.</p>')
        elif self.matches(self.server.finish_path) and self.server.started:
            self.reply(200, FINISH_PAGE)
        else:
            self.reply(404)

    def do_POST(self):
        if (not self.matches(self.server.finish_path) or not self.server.started
                or self.headers.get('Origin') != 'http://' + self.server.authority):
            self.reply(403)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_CALLBACK or self.server.assertion is not None:
                raise ValueError
            callback = self.rfile.read(length).decode('ascii')
            self.server.assertion = read_assertion(callback, self.server.team)
        except (ValueError, OSError):
            self.server.failure = 'the browser returned an invalid or expired enrollment callback for this team'
            self.reply(400)
            return
        self.reply(200)


class LoginServer(HTTPServer):
    def __init__(self, team):
        super().__init__(('127.0.0.1', 0), LoginReceiver)
        self.team = team
        self.authority = f'127.0.0.1:{self.server_port}'
        self.start_path = '/start/' + secrets.token_urlsafe(24)
        self.finish_path = '/finish/' + secrets.token_urlsafe(32)
        self.started = False
        self.assertion = None
        self.failure = None
        self.timeout = 0.3

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(2)
        return conn, address


def _desktop_sign_in(team, url, process_options):
    # The unprivileged child keeps the terminal for the link and possible manual input.
    # Only this socket carries the assertion back to the owner of the registration.
    parent, child = socket.socketpair()
    with parent, child:
        fd = child.fileno()
        with subprocess.Popen([sys.executable, '-I', __file__, str(fd)], pass_fds=(fd,), **process_options) as helper:
            child.close()
            parent.sendall(json.dumps([team, url]).encode())
            parent.shutdown(socket.SHUT_WR)
            with parent.makefile('rb') as reply:
                token = reply.read(MAX_CALLBACK + 1)
            parent.close()
            if helper.wait() or not token or len(token) > MAX_CALLBACK:
                raise ValueError('desktop sign-in did not return a valid enrollment assertion')
    callback = f'com.cloudflare.warp://{team_host(team)}/auth?' + urlencode({'token': token})
    return read_assertion(callback, team)


def sign_in(team, url, manual, *, browser_options=None):
    if browser_options is not None:
        return _desktop_sign_in(team, url, browser_options)
    firefox = shutil.which('firefox') or shutil.which('firefox-esr')
    desktop = os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')
    if manual or not desktop or not firefox or os.geteuid() == 0:
        print(f'Cloudflare sign-in: {url}', flush=True)
        print('After signing in, copy the com.cloudflare.warp:// callback from the Cloudflare '
              'success page into this terminal.', file=sys.stderr)
        if sys.stdin.isatty():
            callback = getpass.getpass('Callback (hidden): ')
        else:
            callback = sys.stdin.readline(MAX_CALLBACK + 2).rstrip('\r\n')
        if not callback:
            raise ValueError('no enrollment callback received')
        return read_assertion(callback, team)

    with LoginServer(team) as server, tempfile.TemporaryDirectory(prefix='unwarp-firefox-') as profile:
        # Firefox expands %s to the escaped native callback. The fragment stays in the
        # browser until the finish page posts it to this single loopback session.
        receiver = f'http://{server.authority}{server.finish_path}#%s'
        handler = {'name': 'Finish this unwarp sign-in', 'uriTemplate': receiver}
        settings = {'defaultHandlersVersion': {}, 'mimeTypes': {},
                    'schemes': {'com.cloudflare.warp': {'action': 2, 'ask': True, 'handlers': [handler]}}}
        Path(profile, 'handlers.json').write_text(json.dumps(settings), encoding='utf-8')
        print(f'To sign in to {team_host(team)}, open this one-time link on this computer:\n'
              f'http://{server.authority}{server.start_path}', flush=True)
        deadline = time.monotonic() + 600
        while not server.started:
            if time.monotonic() >= deadline:
                raise ValueError('the sign-in link expired')
            server.handle_request()
        print('Complete sign-in in the Firefox window opened by unwarp. When prompted, select '
              '"Finish this unwarp sign-in".', file=sys.stderr)
        with subprocess.Popen([firefox, '--no-remote', '--profile', profile, '--new-window', url],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as browser:
            try:
                deadline = time.monotonic() + 600
                while server.assertion is None:
                    if server.failure:
                        raise ValueError(server.failure)
                    if browser.poll() is not None:
                        raise ValueError('the sign-in window closed before returning a callback; '
                                         'use --manual for another browser')
                    if time.monotonic() >= deadline:
                        raise ValueError('browser sign-in timed out')
                    server.handle_request()
                return server.assertion
            finally:
                if browser.poll() is None:
                    browser.terminate()
                    try:
                        browser.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        browser.kill()


if __name__ == '__main__':
    if len(sys.argv) != 2 or not sys.argv[1].isdecimal():
        raise SystemExit('This helper is started by unwarp enroll.')
    try:
        with socket.socket(fileno=int(sys.argv[1])) as channel:
            with channel.makefile('rb') as request:
                team, url = json.load(request)
            assertion, _ = sign_in(team, enrollment_url(team, url), False)
            channel.sendall(assertion.encode('ascii'))
    except (OSError, ValueError, EOFError) as exc:
        print(f'Browser sign-in failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
