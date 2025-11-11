import os
import time
import pytest
import httplib as app
import socket
from typing import Any
from pathlib import Path


class FakeSock(socket.socket):
    def __init__(self, ip: str = '127.0.0.1'):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._ip = ip

    def getpeername(self):
        return (self._ip, 12345)


def setup_function(func: Any) -> None:
    # Reset DOS and rate-limit related global state before each test
    app.ws_dos_violations.clear()
    app.ws_last_message.clear()
    app.ws_messages_per_second.clear()
    app.dos_ip_requests.clear()
    app.dos_blocked_ips.clear()
    app.ws_rate_limit_delays.clear()
    app.ws_rate_limit_counts.clear()
    app.rate_limit_delays.clear()
    app.rate_limit_counts.clear()


def test_check_websocket_dos_disconnect():
    sock = FakeSock('9.9.9.9')

    # Ensure fresh state
    if sock in app.ws_dos_violations: del app.ws_dos_violations[sock]
    if sock in app.ws_messages_per_second: del app.ws_messages_per_second[sock]
    if sock in app.ws_last_message: del app.ws_last_message[sock]

    now = time.time()
    # Simulate message count already at the limit
    app.ws_messages_per_second[sock] = (now, app.DOS_WS_MAX_MESSAGES_PER_SECOND)
    app.ws_dos_violations[sock] = app.DOS_WS_MAX_VIOLATIONS - 1

    # This should increment violations and cause a disconnect (True)
    res = app._check_websocket_dos_protection(sock)
    assert res is True
    assert app.ws_dos_violations.get(sock, 0) >= app.DOS_WS_MAX_VIOLATIONS


def test_ratelimit_count_based_socket_mode():
    sock = FakeSock('127.0.0.1')
    key = (sock, 'count_test')
    # Use count-based: allow 2 requests per 1 second
    # First two should be allowed, third should be rate-limited
    assert app.ratelimit(sock, (2, 1), 'count_test') is False
    assert app.ratelimit(sock, (2, 1), 'count_test') is False
    assert app.ratelimit(sock, (2, 1), 'count_test') is True


@pytest.mark.asyncio
async def test_template_redirect_and_save_load_users(tmp_path: Path):
    # Create static dir and a simple template file
    os.makedirs('static', exist_ok=True)
    tpl_path = os.path.join('static', 'test_template.html')
    with open(tpl_path, 'w', encoding='utf-8') as f:
        f.write('<h1>{{ name }}</h1>')

    # Render template
    out = await app.template('test_template.html', name='Alice')
    assert '<h1>Alice</h1>' in out

    # Redirect
    code, html = await app.redirect('https://example.com')
    assert code == 302
    assert 'https://example.com' in html

    # Save and load users
    app.users.clear(); app.profiles.clear()
    assert app.create_user('u1', 'pass') is True
    tmpfile = tmp_path / 'users.json'
    assert app.save_users(str(tmpfile)) is True

    # Clear and reload
    app.users.clear(); app.profiles.clear()
    assert app.load_users(str(tmpfile)) is True
    assert 'u1' in app.users

    # Cleanup files created
    try:
        os.remove(tpl_path)
        if not os.listdir('static'):
            os.rmdir('static')
    except Exception:
        pass
