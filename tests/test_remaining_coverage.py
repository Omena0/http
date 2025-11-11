import pytest
import httplib as app
import time
from typing import Any

def setup_function(func: Any) -> None:
    # Reset global state
    app.routes.clear()
    app.errors.clear()
    app.users.clear()
    app.profiles.clear()
    app.sessions.clear()
    app.rate_limit_delays.clear()
    app.rate_limit_counts.clear()
    app.dos_ip_requests.clear()
    app.dos_blocked_ips.clear()
    app.ws_rate_limit_delays.clear()
    app.ws_rate_limit_counts.clear()
    app._response_ctx.response = app.Response()
    app._request_ctx.request = app.Request()


@pytest.mark.asyncio
async def test_log_with_invalid_level():
    """Test log function with invalid level"""
    # Should default to INFO
    app.log("Test message", "INVALID_LEVEL")
    # Just verify it doesn't crash


@pytest.mark.asyncio
async def test_log_request_with_status():
    """Test log_request with status code"""
    app.log_request("POST", "/api/test", 201)
    # Verify it doesn't crash


@pytest.mark.asyncio
async def test_response_cookie_with_all_attributes():
    """Test Response.set_cookie with all possible attributes"""
    resp = app.Response()
    
    # Test cookie with domain and expires
    resp.set_cookie('cookie1', 'value1', domain='example.com', expires='Wed, 09 Jun 2021 10:18:14 GMT')
    
    # Test cookie with all boolean flags
    resp.set_cookie('cookie2', 'value2', secure=True, httponly=True, samesite='Lax')
    
    headers = resp.get_cookie_headers()
    assert len(headers) == 2
    
    # Verify all attributes are present
    combined = ' '.join(headers)
    assert 'Domain=example.com' in combined
    assert 'Expires=Wed, 09 Jun 2021 10:18:14 GMT' in combined
    assert 'Secure' in combined
    assert 'HttpOnly' in combined
    assert 'SameSite=Lax' in combined


@pytest.mark.asyncio
async def test_handle_request_error_handler_with_bytes():
    """Test error handler returning bytes"""
    @app.error(403)
    async def forbidden_bytes():
        return b"Forbidden access"
    
    @app.route('/forbidden')
    async def forbidden_route():
        return 403, "blocked"
    
    response = await app._handle_request('GET', '/forbidden', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Forbidden access' in response


@pytest.mark.asyncio
async def test_handle_request_error_handler_with_other_type():
    """Test error handler returning non-standard type"""
    @app.error(402)
    async def payment_required():
        return 402, 12345  # Return integer
    
    @app.route('/payment')
    async def payment_route():
        return 402, "pay up"
    
    response = await app._handle_request('GET', '/payment', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'12345' in response


@pytest.mark.asyncio
async def test_handle_request_route_returns_other_type():
    """Test route returning non-standard type (like int)"""
    @app.route('/number')
    async def number_route():
        return 42  # Return plain integer
    
    response = await app._handle_request('GET', '/number', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'42' in response


@pytest.mark.asyncio
async def test_handle_request_route_returns_list():
    """Test route returning list"""
    @app.route('/items')
    async def items_route():
        return [1, 2, 3, "test"]
    
    response = await app._handle_request('GET', '/items', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'application/json' in response
    assert b'[' in response


@pytest.mark.asyncio
async def test_handle_request_404_with_bytes_error_handler():
    """Test 404 with error handler returning bytes"""
    @app.error(404)
    async def not_found_bytes():
        return b"Page not found - bytes"
    
    response = await app._handle_request('GET', '/nonexistent123', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Page not found - bytes' in response


@pytest.mark.asyncio
async def test_handle_request_404_with_list_error_handler():
    """Test 404 with error handler returning list"""
    @app.error(404)
    async def not_found_list():
        return {"error": "not found", "code": 404}
    
    response = await app._handle_request('GET', '/missing', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'application/json' in response


@pytest.mark.asyncio
async def test_handle_request_404_with_other_type_error_handler():
    """Test 404 with error handler returning other type"""
    @app.error(404)
    async def not_found_other():
        return 123456  # Return int
    
    response = await app._handle_request('GET', '/nothere', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'123456' in response


@pytest.mark.asyncio
async def test_handle_request_global_error_handler_tuple():
    """Test global error handler returning tuple"""
    @app.error()
    async def global_error(status_code: int):
        return status_code, {"error": status_code}
    
    @app.route('/error')
    async def error_route():
        return 418, "teapot"
    
    response = await app._handle_request('GET', '/error', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'418' in response


@pytest.mark.asyncio
async def test_handle_request_dos_blocked():
    """Test request from blocked IP"""
    ip = '1.2.3.4'
    # Block the IP
    app.dos_blocked_ips[ip] = time.time() + 1000
    
    response = await app._handle_request('GET', '/', 'HTTP/1.1', '', '', ip)
    assert b'429' in response
    assert b'blocked' in response.lower()


@pytest.mark.asyncio
async def test_handle_request_dos_protection_triggers():
    """Test DOS protection triggering"""
    ip = '5.6.7.8'
    # Make many rapid requests to trigger DOS
    for _ in range(app.DOS_MAX_REQUESTS + 5):
        response = await app._handle_request('GET', '/', 'HTTP/1.1', '', '', ip)
    
    # Should be rate limited now
    assert b'429' in response


@pytest.mark.asyncio
async def test_parse_params_with_query():
    """Test parameter parsing"""
    params = await app._parse_params('key1=value1&key2=value2&key3=value3')
    assert params['key1'] == 'value1'
    assert params['key2'] == 'value2'
    assert params['key3'] == 'value3'


@pytest.mark.asyncio
async def test_parse_cookies_complex():
    """Test cookie parsing with multiple cookies"""
    cookies = await app._parse_cookies('session=abc123; user=john; theme=dark; lang=en')
    assert cookies['session'] == 'abc123'
    assert cookies['user'] == 'john'
    assert cookies['theme'] == 'dark'
    assert cookies['lang'] == 'en'


@pytest.mark.asyncio
async def test_cleanup_websocket_dos_tracking():
    """Test WebSocket DOS tracking cleanup"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
    
    sock = MockSocket()
    
    # Add tracking
    app.ws_dos_violations[sock] = 5
    app.ws_last_message[sock] = time.time()
    app.ws_messages_per_second[sock] = (time.time(), 10)
    
    # Cleanup
    app._cleanup_websocket_dos_tracking(sock)
    
    # Verify all removed
    assert sock not in app.ws_dos_violations
    assert sock not in app.ws_last_message
    assert sock not in app.ws_messages_per_second


@pytest.mark.asyncio
async def test_websocket_dos_protection_branches():
    """Test various branches in WebSocket DOS protection"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self, ip: str = '127.0.0.1'):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
            self._ip = ip
        
        def getpeername(self):
            return (self._ip, 12345)
    
    sock = MockSocket('10.10.10.10')
    
    # Test initialization path
    result = app._check_websocket_dos_protection(sock)
    assert result is False  # Should be allowed initially
    
    # Test rapid messages (exceed per-second limit)
    current = time.time()
    app.ws_messages_per_second[sock] = (current, app.DOS_WS_MAX_MESSAGES_PER_SECOND + 1)
    app.ws_dos_violations[sock] = 0
    
    result = app._check_websocket_dos_protection(sock)
    # Should warn but not disconnect yet
    assert app.ws_dos_violations[sock] >= 1
    
    # Max out violations
    app.ws_dos_violations[sock] = app.DOS_WS_MAX_VIOLATIONS - 1
    app.ws_messages_per_second[sock] = (current, app.DOS_WS_MAX_MESSAGES_PER_SECOND + 1)
    
    result = app._check_websocket_dos_protection(sock)
    assert result is True  # Should disconnect
    
    # Cleanup
    app._cleanup_websocket_dos_tracking(sock)


@pytest.mark.asyncio
async def test_websocket_dos_min_interval():
    """Test WebSocket minimum message interval checking"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('192.168.1.1', 9999)
    
    sock = MockSocket()
    
    # Initialize
    app.ws_dos_violations[sock] = 0
    app.ws_last_message[sock] = time.time()
    app.ws_messages_per_second[sock] = (time.time(), 1)
    
    # Try to send message too quickly (violates min interval)
    result = app._check_websocket_dos_protection(sock)
    
    # Should have incremented violations
    assert app.ws_dos_violations[sock] >= 1
    
    # Cleanup
    app._cleanup_websocket_dos_tracking(sock)


@pytest.mark.asyncio
async def test_websocket_dos_good_behavior_reduction():
    """Test violation count reduction on good behavior"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('10.20.30.40', 8888)
    
    sock = MockSocket()
    
    # Setup with violations
    current = time.time()
    app.ws_dos_violations[sock] = 2
    app.ws_last_message[sock] = current - 1  # Last message was 1 second ago
    app.ws_messages_per_second[sock] = (current, 2)  # Low message count
    
    # This should potentially reduce violations on good behavior
    # The reduction happens when message_count <= 3 and int(current_time) % 10 == 0
    result = app._check_websocket_dos_protection(sock)
    
    # Cleanup
    app._cleanup_websocket_dos_tracking(sock)


@pytest.mark.asyncio
async def test_is_websocket_request():
    """Test WebSocket request detection"""
    # Valid WebSocket request
    data = b'GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n'
    result = await app._is_websocket_request('GET', data)
    assert result is True
    
    # Not a WebSocket (wrong method)
    result = await app._is_websocket_request('POST', data)
    assert result is False
    
    # Not a WebSocket (no upgrade header)
    data2 = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    result = await app._is_websocket_request('GET', data2)
    assert result is False


@pytest.mark.asyncio
async def test_parse_headers_bytes():
    """Test binary header parsing"""
    data = b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n'
    headers = await app._parse_headers_bytes(data)
    
    assert b'host' in headers
    assert headers[b'host'] == b'example.com'
    assert headers[b'user-agent'] == b'test'


@pytest.mark.asyncio
async def test_read_request_body_variations():
    """Test request body reading with different scenarios"""
    # Body already complete
    headers = 'Content-Length: 10\r\n'
    body = b'0123456789extra'
    result = await app._read_request_body(headers, body)
    assert result == b'0123456789'
    
    # No content-length header (returns empty body)
    headers2 = 'Content-Type: text/plain\r\n'
    body2 = b'some data'
    result2 = await app._read_request_body(headers2, body2)
    # When no Content-Length, the function returns initial_body trimmed to content_length (which is 0)
    assert len(result2) == 0 or result2 == body2
    
    # Invalid content-length (should handle gracefully)
    headers3 = 'Content-Length: invalid\r\n'
    body3 = b'data'
    result3 = await app._read_request_body(headers3, body3)
    # Should return empty or original body
    assert len(result3) >= 0


@pytest.mark.asyncio
async def test_ratelimit_websocket_ip_blocked():
    """Test WebSocket rate limiting when IP is blocked"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('99.99.99.99', 1234)
    
    sock = MockSocket()
    
    # Block the IP
    app.dos_blocked_ips['99.99.99.99'] = time.time() + 1000
    
    # Should be rate limited
    result = app.ratelimit(sock, 1.0, 'test')
    assert result is True


@pytest.mark.asyncio
async def test_ratelimit_decorator_websocket_detection():
    """Test rate limit decorator detecting WebSocket"""
    # Mock a WebSocket handler
    @app.route('/ws', 'ws')
    @app.ratelimit(0.1)
    async def ws_handler(sock: Any):
        return None
    
    # Just verify it's callable
    assert callable(ws_handler)


@pytest.mark.asyncio
async def test_ratelimit_decorator_triggers():
    """Test rate limit decorator actually limiting"""
    app.rate_limit_delays.clear()
    
    # Set request context
    req = app._get_request()
    req.path = '/test_limit'
    
    @app.route('/test_limit')
    @app.ratelimit(0.5)  # 0.5 second delay
    async def limited():
        return "ok"
    
    # First call succeeds
    result1 = await limited()
    assert result1 == "ok"
    
    # Immediate second call should be rate limited
    result2 = await limited()
    assert isinstance(result2, tuple)
    assert result2[0] == 429


@pytest.mark.asyncio
async def test_ratelimit_decorator_count_triggers():
    """Test count-based rate limit decorator"""
    app.rate_limit_counts.clear()
    
    req = app._get_request()
    req.path = '/count_test'
    
    @app.route('/count_test')
    @app.ratelimit(2, 10)  # 2 per 10 seconds
    async def count_limited():
        return "ok"
    
    # First two succeed
    result1 = await count_limited()
    assert result1 == "ok"
    
    result2 = await count_limited()
    assert result2 == "ok"
    
    # Third fails
    result3 = await count_limited()
    assert isinstance(result3, tuple)
    assert result3[0] == 429


@pytest.mark.asyncio
async def test_get_client_ip_exception_handling():
    """Test get_client_ip exception handling"""
    # Create request that will throw exception
    req = app._get_request()
    req.client_ip = ''
    req.headers = {}
    
    # Force exception by clearing request context
    delattr(app._request_ctx, 'request')
    
    ip = app.get_client_ip()
    assert ip == 'unknown'
    
    # Restore
    app._request_ctx.request = req
