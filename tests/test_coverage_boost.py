import pytest
import httplib as app
import os
import json
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
    # Reset response context
    app._response_ctx.response = app.Response()


@pytest.mark.asyncio
async def test_profile_operations():
    """Test user profile management"""
    app.create_user('testuser', 'pass123')
    
    # Get profile (should have default bio)
    profile = app.get_user_profile('testuser')
    assert profile is not None
    assert profile['username'] == 'testuser'
    assert profile['bio'] == ''
    
    # Update profile
    assert app.update_user_profile('testuser', 'My bio') is True
    profile = app.get_user_profile('testuser')
    assert profile['bio'] == 'My bio'
    
    # Non-existent user
    assert app.get_user_profile('nonexistent') is None
    assert app.update_user_profile('nonexistent', 'bio') is False


@pytest.mark.asyncio
async def test_change_username():
    """Test username changes"""
    app.create_user('oldname', 'pass')
    app.update_user_profile('oldname', 'my bio')
    
    # Successful change
    result = app.change_username('oldname', 'newname')
    assert result == 'success'
    assert 'newname' in app.users
    assert 'oldname' not in app.users
    assert app.profiles['newname']['username'] == 'newname'
    assert app.profiles['newname']['bio'] == 'my bio'
    
    # Try to change to existing name
    app.create_user('another', 'pass')
    result = app.change_username('newname', 'another')
    assert result == 'exists'
    
    # Try to change non-existent user
    result = app.change_username('notexist', 'something')
    assert result == 'failed'


@pytest.mark.asyncio
async def test_cookie_operations():
    """Test cookie setting and retrieval"""
    # Set cookie with various options
    app.set_cookie('session', 'abc123', path='/app', max_age=3600, httponly=True, secure=True, samesite='Strict')
    
    resp = app._get_response()
    headers = resp.get_cookie_headers()
    assert len(headers) > 0
    cookie_str = headers[0]
    assert 'session=abc123' in cookie_str
    assert 'Max-Age=3600' in cookie_str
    assert 'HttpOnly' in cookie_str
    assert 'Secure' in cookie_str
    assert 'SameSite=Strict' in cookie_str
    
    # Test get_cookie
    req = app._get_request()
    req.cookies = {'user': 'john', 'theme': 'dark'}
    assert app.get_cookie('user') == 'john'
    assert app.get_cookie('theme') == 'dark'
    assert app.get_cookie('missing', 'default') == 'default'
    
    # Test delete_cookie
    app.delete_cookie('session', path='/app')
    headers = resp.get_cookie_headers()
    # Should have the delete cookie entry
    assert any('Thu, 01 Jan 1970' in h for h in headers)


@pytest.mark.asyncio
async def test_handle_request_with_routes():
    """Test _handle_request with registered routes"""
    # Register a simple route
    @app.route('/test')
    async def test_route():
        return "Hello World"
    
    # Register route that returns tuple
    @app.route('/status')
    async def status_route():
        return 200, "OK"
    
    # Register POST route
    @app.route('/post', 'POST')
    async def post_route():
        return {"status": "created"}
    
    response = await app._handle_request('GET', '/test', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Hello World' in response
    assert b'200 OK' in response
    
    response = await app._handle_request('GET', '/status', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'200 OK' in response
    
    response = await app._handle_request('POST', '/post', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'"status": "created"' in response or b'"status":"created"' in response
    assert b'application/json' in response


@pytest.mark.asyncio
async def test_handle_request_with_error_handlers():
    """Test error handlers"""
    # Register 404 handler
    @app.error(404)
    async def not_found_handler():
        return "Custom 404"
    
    # Register 500 handler
    @app.error(500)
    async def server_error_handler():
        return 500, "Custom 500"
    
    # Register catch-all error handler
    @app.error()
    async def all_errors_handler(status_code: int):
        return status_code, f"Error {status_code}"
    
    # Test 404 with custom handler
    response = await app._handle_request('GET', '/nonexistent', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Custom 404' in response or b'Error 404' in response
    
    # Test route returning error status
    @app.route('/error500')
    async def error_route():
        return 500, "Server error"
    
    response = await app._handle_request('GET', '/error500', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Custom 500' in response or b'Error 500' in response


@pytest.mark.asyncio
async def test_handle_request_with_path_variables():
    """Test routes with path variables"""
    @app.route('/user/<user_id>')
    async def user_route(user_id: str):
        return f"User: {user_id}"
    
    @app.route('/post/<post_id>/comment/<comment_id>')
    async def nested_route(post_id: str, comment_id: str):
        return f"Post {post_id}, Comment {comment_id}"
    
    response = await app._handle_request('GET', '/user/123', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'User: 123' in response
    
    response = await app._handle_request('GET', '/post/456/comment/789', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Post 456, Comment 789' in response


@pytest.mark.asyncio
async def test_static_file_path_normalization():
    """Test static file path normalization"""
    # Test that paths are normalized correctly for static files
    path1 = await app._normalize_path('/file.html')
    assert path1.startswith('static/')
    assert path1.endswith('.html')
    
    # Test with query strings
    path2 = await app._normalize_path('/page?param=value')
    assert '?' not in path2
    assert path2.startswith('static/')


@pytest.mark.asyncio
async def test_url_encode_decode():
    """Test URL encoding and decoding"""
    # Test encoding
    encoded = await app.url_encode("Hello World!")
    assert encoded == "Hello%20World%21"
    
    encoded = await app.url_encode("user@example.com")
    assert "%40" in encoded  # @ should be encoded
    
    # Test decoding
    decoded = await app.url_decode("Hello%20World%21")
    assert decoded == "Hello World!"
    
    decoded = await app.url_decode("user%40example.com")
    assert decoded == "user@example.com"
    
    # Test form data (+ to space)
    decoded = await app.url_decode("first+name")
    assert decoded == "first name"


@pytest.mark.asyncio
async def test_content_type_variants():
    """Test content type detection for various file types"""
    assert await app.get_content_type("file.css") == "text/css"
    assert await app.get_content_type("file.js") == "application/javascript"
    assert await app.get_content_type("file.png") == "image/png"
    assert await app.get_content_type("file.jpg") == "image/jpeg"
    assert await app.get_content_type("file.jpeg") == "image/jpeg"
    assert await app.get_content_type("file.gif") == "image/gif"
    assert await app.get_content_type("file.svg") == "image/svg+xml"
    assert await app.get_content_type("file.json") == "application/json"
    assert await app.get_content_type("file.txt") == "text/plain"
    assert await app.get_content_type("file.xml") == "application/xml"


@pytest.mark.asyncio
async def test_error_shorthand_comprehensive():
    """Test all HTTP status codes"""
    # Test various status codes
    assert await app.get_error_shorthand(100) == "Continue"
    assert await app.get_error_shorthand(204) == "No Content"
    assert await app.get_error_shorthand(301) == "Moved Permanently"
    assert await app.get_error_shorthand(302) == "Found"
    assert await app.get_error_shorthand(400) == "Bad Request"
    assert await app.get_error_shorthand(401) == "Unauthorized"
    assert await app.get_error_shorthand(403) == "Forbidden"
    assert await app.get_error_shorthand(500) == "Internal Server Error"
    assert await app.get_error_shorthand(502) == "Bad Gateway"
    assert await app.get_error_shorthand(503) == "Service Unavailable"


@pytest.mark.asyncio
async def test_count_websocket_connections():
    """Test WebSocket connection counting"""
    # Mock socket with getpeername
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self, ip: str):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
            self._ip = ip
        
        def getpeername(self):
            return (self._ip, 12345)
    
    # Add connections to ws_connections
    sock1 = MockSocket('10.0.0.1')
    sock2 = MockSocket('10.0.0.1')
    sock3 = MockSocket('10.0.0.2')
    
    app.ws_connections['/ws/test'] = [sock1, sock2, sock3]
    
    # Count for specific IP
    count = app.count_websocket_connections('10.0.0.1')
    assert count == 2
    
    count = app.count_websocket_connections('10.0.0.2')
    assert count == 1
    
    count = app.count_websocket_connections('10.0.0.99')
    assert count == 0
    
    # Cleanup
    app.ws_connections.clear()


@pytest.mark.asyncio
async def test_dos_expiry_cleanup():
    """Test DOS protection automatic expiry"""
    import time
    
    ip = '192.168.1.1'
    # Block IP with very short duration
    app.dos_blocked_ips[ip] = time.time() - 1  # Expired 1 second ago
    
    # Check should clean up expired
    blocked = app.is_ip_blocked(ip)
    assert blocked is False
    assert ip not in app.dos_blocked_ips


@pytest.mark.asyncio
async def test_ratelimit_decorator_delay_based():
    """Test delay-based rate limiting decorator"""
    app.rate_limit_delays.clear()
    
    call_count = 0
    
    @app.route('/ratelimited')
    @app.ratelimit(0.1)  # 0.1 second delay
    async def limited_route():
        nonlocal call_count
        call_count += 1
        return f"Call {call_count}"
    
    # First call should succeed
    result = await limited_route()
    assert "Call 1" in result
    
    # Immediate second call should be rate limited
    result = await limited_route()
    assert isinstance(result, tuple)
    assert result[0] == 429


@pytest.mark.asyncio
async def test_ratelimit_decorator_count_based():
    """Test count-based rate limiting decorator"""
    app.rate_limit_counts.clear()
    
    call_count = 0
    
    @app.route('/limited')
    @app.ratelimit(2, 10)  # 2 requests per 10 seconds
    async def limited_route():
        nonlocal call_count
        call_count += 1
        return f"Call {call_count}"
    
    # First two calls should succeed
    result1 = await limited_route()
    assert "Call" in result1
    
    result2 = await limited_route()
    assert "Call" in result2
    
    # Third call should be rate limited
    result3 = await limited_route()
    assert isinstance(result3, tuple)
    assert result3[0] == 429


@pytest.mark.asyncio
async def test_load_users_error_cases(tmp_path):
    """Test load_users with various error conditions"""
    # Test loading non-existent file (should succeed with empty database)
    nonexistent = tmp_path / "nonexistent.json"
    result = app.load_users(str(nonexistent))
    assert result is True
    
    # Test loading invalid JSON
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{ invalid json")
    result = app.load_users(str(invalid_json))
    assert result is False
    
    # Test loading with invalid password hash types
    invalid_data = tmp_path / "invalid_data.json"
    invalid_data.write_text(json.dumps({
        "users": {"user1": 12345},  # Invalid type
        "profiles": {}
    }))
    result = app.load_users(str(invalid_data))
    # Should load but skip invalid entry
    assert result is True


@pytest.mark.asyncio
async def test_ws_broadcast_with_disconnected_sockets():
    """Test ws_broadcast handles disconnected sockets"""
    import socket
    
    class DisconnectedSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def send(self, data):
            raise OSError("Socket is closed")
    
    # Add a disconnected socket
    bad_sock = DisconnectedSocket()
    app.ws_connections['/ws/test'] = [bad_sock]
    
    # Should handle the error gracefully
    await app.ws_broadcast('/ws/test', "test message")
    
    # Cleanup
    app.ws_connections.clear()


@pytest.mark.asyncio
async def test_template_file_not_found():
    """Test template with non-existent file"""
    result = await app.template('nonexistent_file.html', var='value')
    assert isinstance(result, tuple)
    assert result[0] == 404
    assert '404' in result[1]


@pytest.mark.asyncio
async def test_handle_request_bytes_response():
    """Test route returning bytes"""
    @app.route('/bytes')
    async def bytes_route():
        return b"Binary data"
    
    response = await app._handle_request('GET', '/bytes', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Binary data' in response


@pytest.mark.asyncio
async def test_handle_request_with_body():
    """Test POST request with body"""
    @app.route('/submit', 'POST')
    async def submit_route():
        req = app._get_request()
        return f"Body: {req.body}"
    
    response = await app._handle_request('POST', '/submit', 'HTTP/1.1', 'Content-Type: application/json', '{"data": "test"}', '127.0.0.1')
    assert b'Body:' in response


@pytest.mark.asyncio
async def test_client_ip_from_headers():
    """Test client IP extraction with X-Real-IP"""
    req = app._get_request()
    req.client_ip = ''
    req.headers = {'X-Real-IP': '8.8.8.8'}
    
    ip = app.get_client_ip()
    assert ip == '8.8.8.8'
    
    # Test fallback to unknown
    req.client_ip = ''
    req.headers = {}
    ip = app.get_client_ip()
    assert ip == 'unknown'


@pytest.mark.asyncio
async def test_response_cookie_formatting():
    """Test Response cookie header formatting"""
    resp = app.Response()
    
    # Test with domain
    resp.set_cookie('test', 'value', domain='example.com')
    headers = resp.get_cookie_headers()
    assert any('Domain=example.com' in h for h in headers)
    
    # Test with expires
    resp.set_cookie('test2', 'value2', expires='Wed, 09 Jun 2021 10:18:14 GMT')
    headers = resp.get_cookie_headers()
    assert any('Expires=Wed, 09 Jun 2021 10:18:14 GMT' in h for h in headers)


@pytest.mark.asyncio 
async def test_error_handler_with_dict_response():
    """Test error handler returning dict/list"""
    @app.error(403)
    async def forbidden_handler():
        return {"error": "Forbidden", "code": 403}
    
    @app.route('/forbidden')
    async def forbidden_route():
        return 403, "Access denied"
    
    response = await app._handle_request('GET', '/forbidden', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'application/json' in response
    assert b'"error"' in response or b'"code"' in response


@pytest.mark.asyncio
async def test_handle_request_http_version_check():
    """Test HTTP version validation"""
    response = await app._handle_request('GET', '/', 'HTTP/1.0', '', '', '127.0.0.1')
    assert b'505' in response
    assert b'HTTP Version Not Supported' in response
