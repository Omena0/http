import pytest
import httplib as app
import os
import socket
import types

@pytest.mark.asyncio
async def test_normalize_path_variants():
    assert await app._normalize_path('/') == 'static/index.html'
    assert await app._normalize_path('/about') == 'static/about.html'
    assert await app._normalize_path('/static/page.html') == 'static/page.html'
    # traversal should default to index
    assert await app._normalize_path('../etc/passwd') == 'static/index.html'

@pytest.mark.asyncio
async def test_parsers():
    headers = 'Host: example.com\nX-Test: value\n'
    parsed = await app._parse_headers(headers)
    assert parsed['Host'] == 'example.com'
    assert parsed['X-Test'] == 'value'

    params = await app._parse_params('a=1&b=two')
    assert params['a'] == '1' and params['b'] == 'two'

    cookies = await app._parse_cookies('a=1; b=2')
    assert cookies['a'] == '1' and cookies['b'] == '2'

@pytest.mark.asyncio
async def test_error_shorthand_and_content_type():
    assert await app.get_error_shorthand(200) == 'OK'
    assert await app.get_error_shorthand(418) == "I'm a teapot"
    assert await app.get_error_shorthand(999) == 'Unknown Error'

    assert await app.get_content_type('index.html') == 'text/html'
    assert await app.get_content_type('file.unknown') == 'text/plain'

def test_client_ip_and_request_context(monkeypatch):
    # prepare request context
    req = app._get_request()
    req.client_ip = '1.2.3.4'
    assert app.get_client_ip() == '1.2.3.4'
    req.client_ip = ''
    req.headers['X-Forwarded-For'] = '5.6.7.8, 9.9.9.9'
    assert app.get_client_ip() == '5.6.7.8'
    req.headers.clear()

def test_dos_and_blocking():
    ip = '10.0.0.1'
    # ensure clean
    if ip in app.dos_ip_requests: del app.dos_ip_requests[ip]
    if ip in app.dos_blocked_ips: del app.dos_blocked_ips[ip]

    # simulate many requests quickly to trigger block
    for _ in range(app.DOS_MAX_REQUESTS + 1):
        blocked = app.check_dos_protection(ip)
    assert app.is_ip_blocked(ip) is True
    blocked_ips = app.get_blocked_ips()
    assert ip in blocked_ips
    # unblock
    assert app.unblock_ip(ip) is True
    assert app.is_ip_blocked(ip) is False

def test_dos_stats_empty():
    stats = app.get_dos_stats()
    assert 'tracked_ips' in stats and 'blocked_ips' in stats

@pytest.mark.asyncio
async def test_match_route_and_build_response():
    vars = await app._match_route('/user/123', '/user/<id>')
    assert vars == {'id': '123'}
    assert await app._match_route('/a/b', '/a/b') == {}
    assert await app._match_route('/a/b', '/a/c') is None

    # test response building with cookies
    resp = app._get_response()
    resp.set_cookie('s', 'v', max_age=10, httponly=True)
    header = await app._build_response(200, 'text/plain')
    assert b'Set-Cookie' in header

def test_user_operations_and_sessions(tmp_path):
    app.users.clear(); app.profiles.clear(); app.sessions.clear()
    assert app.create_user('x', 'p') is True
    assert app.user_exists('x')
    assert app.login('x', 'p') is True
    assert app.edit_user('x', 'new') is True
    assert app.delete_user('x') is True

    app.create_user('y', 'p')
    token = app.start_session('y')
    assert app.verify_session(token)
    assert app.get_username(token) == 'y'
    app.end_session(token)
    assert not app.verify_session(token)

@pytest.mark.asyncio
async def test_ratelimit_decorator_mode():
    # Decorator mode: ensure it returns a callable
    dec = app.ratelimit(0.1)
    @dec
    async def f():
        return 'ok'
    assert callable(f)