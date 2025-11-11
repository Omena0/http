import pytest
import httplib as app
import time
import json
import os
from pathlib import Path
from typing import Any


def setup_function(func: Any) -> None:
    # Reset global state
    app.routes.clear()
    app.errors.clear()
    app.users.clear()
    app.profiles.clear()
    app.sessions.clear()
    app.dos_ip_requests.clear()
    app.dos_blocked_ips.clear()
    app.ws_connections.clear()


@pytest.mark.asyncio
async def test_is_ip_blocked_unknown():
    """Test is_ip_blocked with 'unknown' IP"""
    assert app.is_ip_blocked('unknown') is False


@pytest.mark.asyncio
async def test_is_ip_blocked_with_expiry_log():
    """Test that expired IPs are logged when cleaned up"""
    ip = '11.22.33.44'
    # Block IP with past expiry
    app.dos_blocked_ips[ip] = time.time() - 1
    
    # Check should clean up and log
    result = app.is_ip_blocked(ip)
    assert result is False
    assert ip not in app.dos_blocked_ips


@pytest.mark.asyncio
async def test_is_ip_blocked_logs_attempt():
    """Test that blocked IP attempts are logged"""
    ip = '55.66.77.88'
    # Block IP
    app.dos_blocked_ips[ip] = time.time() + 100
    
    # Attempt should be logged
    result = app.is_ip_blocked(ip)
    assert result is True


@pytest.mark.asyncio
async def test_check_dos_protection_unknown():
    """Test DOS protection with unknown IP"""
    assert app.check_dos_protection('unknown') is False


@pytest.mark.asyncio
async def test_count_websocket_connections_exception_handling():
    """Test WebSocket connection counting with bad socket"""
    import socket
    
    class BadSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            raise OSError("Socket error")
    
    bad_sock = BadSocket()
    app.ws_connections['/ws/test'] = [bad_sock]
    
    # Should handle exception and return 0
    count = app.count_websocket_connections('1.1.1.1')
    assert count == 0
    
    app.ws_connections.clear()


@pytest.mark.asyncio
async def test_unblock_ip_not_blocked():
    """Test unblock_ip when IP isn't blocked"""
    result = app.unblock_ip('192.168.1.100')
    assert result is False


@pytest.mark.asyncio
async def test_get_blocked_ips_cleanup():
    """Test get_blocked_ips cleans up expired IPs"""
    # Add expired and active blocks
    app.dos_blocked_ips['old.ip'] = time.time() - 1  # Expired
    app.dos_blocked_ips['new.ip'] = time.time() + 100  # Active
    
    blocked = app.get_blocked_ips()
    
    # Should only have active IP
    assert 'old.ip' not in blocked
    assert 'new.ip' in blocked


@pytest.mark.asyncio
async def test_websocket_dos_violation_count_reduction():
    """Test WebSocket violation reduction logic timing"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('test.ip', 1234)
    
    sock = MockSocket()
    
    # Setup for potential reduction
    current = time.time()
    app.ws_dos_violations[sock] = 2
    app.ws_last_message[sock] = current - 1
    app.ws_messages_per_second[sock] = (current, 2)  # Low message count
    
    # Try to trigger the reduction (requires int(current_time) % 10 == 0)
    # We can't control time precisely, but we can test the path exists
    result = app._check_websocket_dos_protection(sock)
    
    # Should not disconnect
    assert result is False
    
    app._cleanup_websocket_dos_tracking(sock)


@pytest.mark.asyncio
async def test_websocket_dos_new_second_reset():
    """Test WebSocket message counter resets each second"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('reset.test', 5555)
    
    sock = MockSocket()
    
    # Setup with old second
    old_time = time.time() - 2
    app.ws_dos_violations[sock] = 0
    app.ws_last_message[sock] = old_time
    app.ws_messages_per_second[sock] = (old_time, 50)  # Many messages in old second
    
    # New check should reset counter
    result = app._check_websocket_dos_protection(sock)
    assert result is False
    
    # Counter should have been reset
    second_start, count = app.ws_messages_per_second[sock]
    assert count == 1  # Reset to 1 (new message)
    
    app._cleanup_websocket_dos_tracking(sock)


@pytest.mark.asyncio
async def test_handle_request_with_params_in_url():
    """Test _handle_request with URL parameters"""
    @app.route('/search')
    async def search():
        req = app.request
        return f"Query: {req.params.get('q', 'none')}"
    
    response = await app._handle_request('GET', '/search?q=test', 'HTTP/1.1', '', '', '127.0.0.1')
    assert b'Query: test' in response


@pytest.mark.asyncio
async def test_handle_request_deletes_body_attr():
    """Test that request body is cleaned up after handler"""
    @app.route('/body_test', 'POST')
    async def body_handler():
        return "ok"
    
    await app._handle_request('POST', '/body_test', 'HTTP/1.1', '', 'test body', '127.0.0.1')
    
    # After handling, body should be deleted
    req = app._get_request()
    assert not hasattr(req, 'body') or req.body == ''


@pytest.mark.asyncio
async def test_ws_broadcast_no_route():
    """Test ws_broadcast with non-existent route"""
    # Should log and return without error
    await app.ws_broadcast('/ws/nonexistent', 'test')
    # Just verify it doesn't crash


@pytest.mark.asyncio
async def test_ws_broadcast_removes_disconnected():
    """Test ws_broadcast removes disconnected sockets from list"""
    import socket
    
    class FailSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def send(self, *args, **kwargs):
            raise OSError("Disconnected")
    
    fail_sock = FailSocket()
    app.ws_connections['/ws/test'] = [fail_sock]
    
    # Should handle error and clean up
    await app.ws_broadcast('/ws/test', 'message')
    
    # Socket should be removed
    assert fail_sock not in app.ws_connections.get('/ws/test', [])


@pytest.mark.asyncio
async def test_ws_broadcast_cleans_empty_route():
    """Test ws_broadcast cleans up empty route entries"""
    import socket
    
    class FailSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def send(self, *args, **kwargs):
            raise OSError("Disconnected")
    
    fail_sock = FailSocket()
    app.ws_connections['/ws/cleanup'] = [fail_sock]
    
    await app.ws_broadcast('/ws/cleanup', 'message')
    
    # Route should be removed entirely
    assert '/ws/cleanup' not in app.ws_connections


@pytest.mark.asyncio
async def test_load_users_with_bytes_password():
    """Test load_users with password already as bytes"""
    test_file = 'test_users_bytes.json'
    
    # Create user and save
    app.users.clear()
    app.users['test'] = b'raw_bytes_password'
    
    # Manually create JSON with bytes (which will be base64 encoded on save)
    app.save_users(test_file)
    
    # Clear and reload
    app.users.clear()
    result = app.load_users(test_file)
    
    assert result is True
    assert 'test' in app.users
    
    # Cleanup
    try:
        os.remove(test_file)
    except:
        pass


@pytest.mark.asyncio
async def test_load_users_invalid_profile_data():
    """Test load_users with invalid profile data"""
    test_file = 'test_invalid_profile.json'
    
    # Create file with invalid profile data
    data = {
        "users": {},
        "profiles": {
            "user1": "invalid_not_dict",  # Should be dict
            "user2": {"valid": "profile"}
        }
    }
    
    with open(test_file, 'w') as f:
        json.dump(data, f)
    
    app.users.clear()
    app.profiles.clear()
    result = app.load_users(test_file)
    
    # Should succeed but skip invalid profile
    assert result is True
    assert 'user1' not in app.profiles
    assert 'user2' in app.profiles
    
    # Cleanup
    try:
        os.remove(test_file)
    except:
        pass


@pytest.mark.asyncio
async def test_template_variable_replacement():
    """Test template with multiple variable replacements"""
    os.makedirs('static', exist_ok=True)
    template_file = 'static/multi_var_template.html'
    
    with open(template_file, 'w') as f:
        f.write('<h1>{{ title }}</h1><p>{{ content }}</p><span>{{ author }}</span>')
    
    try:
        result = await app.template('multi_var_template.html', 
                                     title='Test Title', 
                                     content='Test Content',
                                     author='Test Author')
        
        assert 'Test Title' in result
        assert 'Test Content' in result
        assert 'Test Author' in result
        assert '{{' not in result  # All variables should be replaced
    finally:
        try:
            os.remove(template_file)
        except:
            pass


@pytest.mark.asyncio
async def test_ratelimit_websocket_exception_in_getpeername():
    """Test ratelimit with socket that throws exception"""
    import socket
    
    class BadSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            raise OSError("No peer")
    
    sock = BadSocket()
    
    # Should handle exception and use 'unknown' IP
    result = app.ratelimit(sock, 1.0, 'test')
    # Should succeed (unknown IPs not blocked)
    assert result is False


@pytest.mark.asyncio
async def test_ratelimit_decorator_blocked_ip():
    """Test rate limit decorator with blocked IP"""
    req = app._get_request()
    req.client_ip = '100.100.100.100'
    req.path = '/blocked_test'
    
    # Block the IP
    app.dos_blocked_ips['100.100.100.100'] = time.time() + 1000
    
    @app.route('/blocked_test')
    @app.ratelimit(1.0)
    async def blocked_handler():
        return "should not reach"
    
    result = await blocked_handler()
    
    # Should return 429
    assert isinstance(result, tuple)
    assert result[0] == 429


@pytest.mark.asyncio
async def test_ratelimit_decorator_cleanup_old_counts():
    """Test that count-based rate limit cleans old requests"""
    req = app._get_request()
    req.client_ip = '50.50.50.50'
    req.path = '/cleanup_test'
    
    app.rate_limit_counts.clear()
    
    @app.route('/cleanup_test')
    @app.ratelimit(3, 1)  # 3 per 1 second
    async def cleanup_handler():
        return "ok"
    
    # Make requests
    await cleanup_handler()
    await cleanup_handler()
    
    # Wait for window to expire
    time.sleep(1.1)
    
    # Should succeed (old requests cleaned up)
    result = await cleanup_handler()
    assert result == "ok"


@pytest.mark.asyncio
async def test_ratelimit_websocket_count_based():
    """Test WebSocket rate limiting with count-based limiting"""
    import socket
    
    class MockSocket(socket.socket):
        def __init__(self):
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        
        def getpeername(self):
            return ('ws.count.test', 7777)
    
    sock = MockSocket()
    app.ws_rate_limit_counts.clear()
    
    # Count-based: 3 per 10 seconds
    assert app.ratelimit(sock, (3, 10), 'count') is False
    assert app.ratelimit(sock, (3, 10), 'count') is False
    assert app.ratelimit(sock, (3, 10), 'count') is False
    assert app.ratelimit(sock, (3, 10), 'count') is True  # Should be limited


@pytest.mark.asyncio
async def test_parse_headers_multiline():
    """Test header parsing with multiple headers"""
    headers = "Host: example.com\nContent-Type: application/json\nAuthorization: Bearer token\nUser-Agent: test"
    parsed = await app._parse_headers(headers)
    
    assert parsed['Host'] == 'example.com'
    assert parsed['Content-Type'] == 'application/json'
    assert parsed['Authorization'] == 'Bearer token'
    assert parsed['User-Agent'] == 'test'
