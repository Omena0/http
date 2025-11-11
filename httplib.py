from typing import Protocol, Callable, Any, NoReturn, TypeVar, Awaitable, Union, overload
from traceback import format_exc
from functools import wraps
import threading
import asyncio
import hashlib
import socket
import base64
import json
import time
import hmac
import os

s = socket.socket()

# Type variable for the decorated function
F = TypeVar('F', bound=Callable[..., Awaitable[Any]])

class RouteHandler(Protocol):
    async def __call__(self, *args: Any, **kwargs: Any) -> str | bytes | tuple[int, str | bytes] | None | NoReturn: ...

class ErrorHandler(Protocol):
    async def __call__(self, *args: Any, **kwargs: Any) -> str | bytes | tuple[int, str | bytes]: ...

## Routing ##
routes: list[tuple[str, str, RouteHandler]] = []
errors: dict[int | None, ErrorHandler] = {}

## Websockets ##
ws_connections: dict[str, list[socket.socket]] = {}

## Logins ##
users: dict[str, bytes] = {}
profiles: dict[str, dict[str, Any]] = {}
sessions: dict[str, dict[str, Any]] = {}

## Rate limiting ##
# WebSocket rate limiting
ws_rate_limit_delays: dict[tuple[socket.socket, str], float] = {}
ws_rate_limit_counts: dict[tuple[socket.socket, str], list[float]] = {}

# HTTP rate limiting
rate_limit_delays: dict[tuple[str, str], float] = {}
rate_limit_counts: dict[tuple[str, str], list[float]] = {}
rate_limit_lock = threading.Lock()

## DOS Protection ##
# Global IP-based DOS protection
dos_ip_requests: dict[str, list[float]] = {}  # IP -> list of request timestamps
dos_blocked_ips: dict[str, float] = {}  # IP -> block expiry time
dos_lock = threading.Lock()

# DOS protection configuration
DOS_WINDOW_SIZE = 1  # seconds
DOS_MAX_REQUESTS = 100  # max requests per window per IP
DOS_BLOCK_DURATION = 3  # seconds to block IP after DOS detection
DOS_WEBSOCKET_MAX_CONNECTIONS = 100  # max WebSocket connections per IP

# WebSocket-specific DOS protection
ws_dos_violations: dict[socket.socket, int] = {}  # socket -> violation count
ws_last_message: dict[socket.socket, float] = {}  # socket -> last message time
ws_messages_per_second: dict[socket.socket, tuple[float, int]] = {}  # socket -> (second_start, count)
ws_dos_lock = threading.Lock()

# WebSocket DOS protection configuration
DOS_WS_MAX_MESSAGES_PER_SECOND = 100  # max WebSocket messages per second
DOS_WS_MIN_MESSAGE_INTERVAL = 0.001  # minimum seconds between messages (1ms)
DOS_WS_MAX_VIOLATIONS = 3  # max violations before disconnection

# Simple log function with log levels
LOG_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
log_level = LOG_LEVELS['INFO']

# Refined log level colors (bold, specific colors)
LOG_LEVEL_COLORS = {
    "DEBUG": "\033[90;1m",      # Bold gray
    "INFO": "\033[94;1m",       # Bold blue
    "WARNING": "\033[93;1m",    # Bold yellow
    "ERROR": "\033[91;1m",      # Bold red
    "CRITICAL": "\033[41;97;1m"  # Bold white on dark red bg
}
RESET_COLOR = "\033[0m"

# HTTP method colors for log_request
METHOD_COLORS = {
    'GET': '\033[92m',      # Green
    'POST': '\033[96m',     # Cyan
    'PUT': '\033[95m',      # Magenta
    'DELETE': '\033[91m',   # Red
    'PATCH': '\033[93m',    # Yellow
    'OPTIONS': '\033[90m',  # Gray
}

def log(message: str, level: str = "INFO") -> None:
    """
    Log a message with a specified level and timestamp.

    Supports colored output for different log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL.
    Messages are only printed if their level meets the current log level threshold.

    Args:
        message: The message to log
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.

    Example:
        ```python
        log("Server starting", "INFO")
        log("User authentication failed", "WARNING")
        log("Database connection error", "ERROR")
        ```
    """
    level = level.upper()
    if level not in LOG_LEVELS:
        level = "INFO"
    if LOG_LEVELS[level] >= log_level:
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        color = LOG_LEVEL_COLORS.get(level, "")

        # Timestamp is plain, log level is bold and colored
        print(f"[{ts}] {color}{level:>8}{RESET_COLOR}: {message}")

def log_request(method: str, path: str, status: int | None = None) -> None:
    """
    Log HTTP requests with colored method names.

    Automatically formats and logs HTTP requests with colored method names for better readability.
    Each HTTP method has its own color (GET=green, POST=cyan, etc.).

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        path: Request path
        status: Optional HTTP status code to include in the log

    Example:
        ```python
        log_request("GET", "/api/users")
        log_request("POST", "/login", 200)
        ```
    """
    method = method.upper()
    color = METHOD_COLORS.get(method, '')
    reset = RESET_COLOR if color else ''
    status_str = f" {status}" if status is not None else ""
    log(f"{color}{method}{reset} {path}{status_str}", "INFO")

# Request context
class Request:
    def __init__(self):
        self.headers: dict[str, str] = {}
        self.params: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.path: str = ''
        self.method: str = ''
        self.body: str = ''
        self.client_ip: str = ''

# Response context for managing cookies
class Response:
    def __init__(self):
        self.cookies: dict[str, dict[str, str]] = {}  # cookie_name -> {value, path, domain, expires, etc}

    def set_cookie(self, name: str, value: str, path: str = '/', domain: str = '',
                   expires: str = '', max_age: int = 0, secure: bool = False,
                   httponly: bool = False, samesite: str = ''):
        """Set a cookie with optional attributes"""
        cookie_attrs = {'value': value}
        if path: cookie_attrs['path'] = path
        if domain: cookie_attrs['domain'] = domain
        if expires: cookie_attrs['expires'] = expires
        if max_age > 0: cookie_attrs['max_age'] = str(max_age)
        if secure: cookie_attrs['secure'] = 'true'
        if httponly: cookie_attrs['httponly'] = 'true'
        if samesite: cookie_attrs['samesite'] = samesite

        self.cookies[name] = cookie_attrs

    def delete_cookie(self, name: str, path: str = '/'):
        """Delete a cookie by setting it to expire in the past"""
        self.set_cookie(name, '', path=path, expires='Thu, 01 Jan 1970 00:00:00 GMT')

    def get_cookie_headers(self) -> list[str]:
        """Generate Set-Cookie headers for all cookies"""
        headers: list[str] = []
        for name, attrs in self.cookies.items():
            cookie_header = f"{name}={attrs['value']}"

            for attr_name, attr_value in attrs.items():
                if attr_name == 'value':
                    continue
                elif attr_name in ['secure', 'httponly']:
                    if attr_value == 'true':
                        cookie_header += f"; {attr_name.replace('httponly', 'HttpOnly').replace('secure', 'Secure')}"
                elif attr_name == 'max_age':
                    cookie_header += f"; Max-Age={attr_value}"
                elif attr_name == 'samesite':
                    cookie_header += f"; SameSite={attr_value}"
                else:
                    cookie_header += f"; {attr_name.capitalize()}={attr_value}"

            headers.append(cookie_header)
        return headers

# Use thread-local storage for safety with threads
_request_ctx = threading.local()
_response_ctx = threading.local()

def _get_request() -> Request:
    if not hasattr(_request_ctx, 'request'):
        _request_ctx.request = Request()
    return _request_ctx.request

def _get_response() -> Response:
    if not hasattr(_response_ctx, 'response'):
        _response_ctx.response = Response()
    return _response_ctx.response

# Flask-like global request and response objects
request = _get_request()
response = _get_response()

# Helpers
async def _normalize_path(path: str) -> str:
    # Remove query string if present
    path = path.split('?', 1)[0]

    # Default to index.html for root
    if path in ('', '/'):
        path = '/index.html'

    # Prevent directory traversal
    path = os.path.normpath(path).replace('\\', '/')
    if '..' in path or path.startswith('../') or path.startswith('/..'):
        path = '/index.html'

    # Ensure path starts with /static unless already present
    if not path.removeprefix('/').startswith('static/'):
        # Remove leading slash to avoid double slash
        path = '/static' + (path if path.startswith('/') else f'/{path}')

    # Ensure .html extension
    if '.' not in path:
        path += '.html'

    return path.removeprefix('/')

# Parsers
async def _parse_headers(headers: str) -> dict[str, str]:
    header_dict: dict[str, str] = {}
    for line in headers.split('\n'):
        line = line.strip()
        if line:
            key, value = line.split(':', 1)
            header_dict[key.strip()] = value.strip()
    return header_dict

async def _parse_params(query: str) -> dict[str,str]:
    params:dict[str,str] = {}
    if query:
        for param in query.split('&'):
            key, value = param.split('=', 1)
            params[key] = value
    return params

async def _parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse cookies from Cookie header"""
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies

    # Split cookies by semicolon and parse each one
    for cookie in cookie_header.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    return cookies

# Urlencode
async def url_decode(value: str) -> str:
    """
    Decode a URL-encoded string.

    Converts percent-encoded characters (%20, %21, etc.) back to their original characters.
    Also converts '+' characters to spaces (common in form data).

    Args:
        value: URL-encoded string to decode

    Returns:
        Decoded string

    Example:
        ```python
        decoded = await url_decode("Hello%20World%21")  # "Hello World!"
        form_data = await url_decode("first+name")      # "first name"
        ```
    """
    # Replace + with space (optional, for form data)
    value = value.replace('+', ' ')
    # Find all percent-encoded bytes
    bytes_list = bytearray()
    i = 0
    while i < len(value):
        if value[i] == '%' and i + 2 < len(value):
            bytes_list.append(int(value[i+1:i+3], 16))
            i += 3
        else:
            bytes_list.append(ord(value[i]))
            i += 1

    return bytes_list.decode('utf-8')

async def url_encode(value: str) -> str:
    """
    Encode a string for safe use in URLs.

    Converts special characters to percent-encoded format (%20, %21, etc.).
    Alphanumeric characters and -_.~ are left unchanged as they're safe.

    Args:
        value: String to encode

    Returns:
        URL-encoded string

    Example:
        ```python
        encoded = await url_encode("Hello World!")  # "Hello%20World%21"
        safe_param = await url_encode("user@domain.com")  # "user%40domain.com"
        ```
    """
    encoded:list[str] = []
    for char in value:
        if char.isalnum() or char in '-_.~':
            encoded.append(char)
        else:
            encoded.append(f'%{ord(char):02X}')
    return ''.join(encoded)

async def get_error_shorthand(err_code: int) -> str:
    """
    Get the standard HTTP status text for a given status code.

    Returns the official HTTP status message for common status codes (200 OK, 404 Not Found, etc.).

    Args:
        err_code: HTTP status code

    Returns:
        Status text string, or 'Unknown Error' for unrecognized codes

    Example:
        ```python
        text = await get_error_shorthand(200)  # "OK"
        text = await get_error_shorthand(404)  # "Not Found"
        text = await get_error_shorthand(500)  # "Internal Server Error"
        ```
    """
    shorthand = {
        100: 'Continue',
        101: 'Switching Protocols',
        102: 'Processing',
        103: 'Early Hints',
        200: 'OK',
        201: 'Created',
        202: 'Accepted',
        203: 'Non-Authoritative Information',
        204: 'No Content',
        205: 'Reset Content',
        206: 'Partial Content',
        207: 'Multi-Status',
        208: 'Already Reported',
        226: 'IM Used',
        300: 'Multiple Choices',
        301: 'Moved Permanently',
        302: 'Found',
        303: 'See Other',
        304: 'Not Modified',
        305: 'Use Proxy',
        307: 'Temporary Redirect',
        308: 'Permanent Redirect',
        400: 'Bad Request',
        401: 'Unauthorized',
        402: 'Payment Required',
        403: 'Forbidden',
        404: 'Not Found',
        405: 'Method Not Allowed',
        406: 'Not Acceptable',
        407: 'Proxy Authentication Required',
        408: 'Request Timeout',
        409: 'Conflict',
        410: 'Gone',
        411: 'Length Required',
        412: 'Precondition Failed',
        413: 'Payload Too Large',
        414: 'URI Too Long',
        415: 'Unsupported Media Type',
        416: 'Range Not Satisfiable',
        417: 'Expectation Failed',
        418: "I'm a teapot",
        421: 'Misdirected Request',
        422: 'Unprocessable Entity',
        423: 'Locked',
        424: 'Failed Dependency',
        425: 'Too Early',
        426: 'Upgrade Required',
        428: 'Precondition Required',
        429: 'Too Many Requests',
        431: 'Request Header Fields Too Large',
        451: 'Unavailable For Legal Reasons',
        500: 'Internal Server Error',
        501: 'Not Implemented',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout',
        505: 'HTTP Version Not Supported',
        506: 'Variant Also Negotiates',
        507: 'Insufficient Storage',
        508: 'Loop Detected',
        510: 'Not Extended',
        511: 'Network Authentication Required'
    }
    return shorthand.get(err_code, 'Unknown Error')

async def get_content_type(path: str) -> str:
    """
    Determine the MIME content type based on file extension.

    Returns the appropriate Content-Type header value for common file extensions.

    Args:
        path: File path or filename

    Returns:
        MIME type string (e.g., 'text/html', 'application/json')

    Example:
        ```python
        content_type = await get_content_type("index.html")    # "text/html"
        content_type = await get_content_type("api.json")      # "application/json"
        content_type = await get_content_type("style.css")     # "text/css"
        ```
    """
    if path.endswith('.html'):
        return 'text/html'
    elif path.endswith('.css'):
        return 'text/css'
    elif path.endswith('.js'):
        return 'application/javascript'
    elif path.endswith('.png'):
        return 'image/png'
    elif path.endswith('.jpg') or path.endswith('.jpeg'):
        return 'image/jpeg'
    elif path.endswith('.gif'):
        return 'image/gif'
    elif path.endswith('.svg'):
        return 'image/svg+xml'
    elif path.endswith('.json'):
        return 'application/json'
    elif path.endswith('.txt'):
        return 'text/plain'
    elif path.endswith('.xml'):
        return 'application/xml'
    else:
        return 'text/plain'

def get_client_ip() -> str:
    """
    Extract the client IP address from the current request context.

    Attempts to get the real client IP by checking multiple sources in order:
    1. Direct client IP from socket connection
    2. X-Forwarded-For header (for proxy scenarios)
    3. X-Real-IP header
    4. Falls back to 'unknown' if none available

    Returns:
        Client IP address as string, or 'unknown' if unavailable

    Example:
        ```python
        @route('/api/user-info')
        async def user_info():
            client_ip = get_client_ip()
            return f"Your IP is: {client_ip}"
        ```
    """
    try:
        req = _get_request()

        # First check if we have the actual client IP from the socket
        if req.client_ip:
            return req.client_ip

        # Try to get from X-Forwarded-For header
        forwarded = req.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()

        # Try X-Real-IP
        real_ip = req.headers.get('X-Real-IP', '')
        if real_ip:
            return real_ip

        # Fallback to a default
        return 'unknown'
    except Exception:
        return 'unknown'

def is_ip_blocked(ip: str) -> bool:
    """
    Check if an IP address is currently blocked due to DOS protection.

    Args:
        ip: IP address to check

    Returns:
        True if IP is blocked, False otherwise
    """
    if ip == 'unknown':
        return False

    current_time = time.time()

    with dos_lock:
        # Clean up expired blocks
        expired_ips = [blocked_ip for blocked_ip, expiry in dos_blocked_ips.items()
                      if current_time > expiry]
        for blocked_ip in expired_ips:
            del dos_blocked_ips[blocked_ip]
            log(f"Unblocked IP {blocked_ip} (block expired)", "INFO")

        # Check if IP is currently blocked
        if ip in dos_blocked_ips:
            remaining_time = dos_blocked_ips[ip] - current_time
            log(f"Blocked IP {ip} attempted request (blocked for {remaining_time:.1f}s more)", "WARNING")
            return True

    return False

def check_dos_protection(ip: str) -> bool:
    """
    Check if an IP should be blocked for DOS protection.

    Args:
        ip: IP address to check

    Returns:
        True if IP should be blocked, False if allowed
    """
    if ip == 'unknown':
        return False

    current_time = time.time()

    with dos_lock:
        # Initialize request history for new IPs
        if ip not in dos_ip_requests:
            dos_ip_requests[ip] = []

        # Clean old requests outside the window
        window_start = current_time - DOS_WINDOW_SIZE
        dos_ip_requests[ip] = [req_time for req_time in dos_ip_requests[ip]
                              if req_time > window_start]

        # Add current request
        dos_ip_requests[ip].append(current_time)

        # Check if DOS threshold exceeded
        if len(dos_ip_requests[ip]) > DOS_MAX_REQUESTS:
            # Block the IP
            dos_blocked_ips[ip] = current_time + DOS_BLOCK_DURATION
            log(f"DOS protection activated: blocked IP {ip} for {DOS_BLOCK_DURATION}s ({len(dos_ip_requests[ip])} requests in {DOS_WINDOW_SIZE}s)", "ERROR")

            # Clear request history to prevent memory bloat
            dos_ip_requests[ip] = []
            return True

    return False

def count_websocket_connections(ip: str) -> int:
    """
    Count active WebSocket connections for an IP address.

    Args:
        ip: IP address to count connections for

    Returns:
        Number of active WebSocket connections for this IP
    """
    count = 0
    for route_connections in ws_connections.values():
        for sock in route_connections:
            try:
                peer_addr = sock.getpeername()
                if peer_addr and peer_addr[0] == ip:
                    count += 1
            except Exception:
                # Socket might be closed, ignore
                pass
    return count

def unblock_ip(ip: str) -> bool:
    """
    Manually unblock an IP address.

    Args:
        ip: IP address to unblock

    Returns:
        True if IP was blocked and is now unblocked, False if IP wasn't blocked
    """
    with dos_lock:
        if ip in dos_blocked_ips:
            del dos_blocked_ips[ip]
            log(f"Manually unblocked IP {ip}", "INFO")
            return True
        return False

def get_blocked_ips() -> dict[str, float]:
    """
    Get all currently blocked IPs and their unblock times.

    Returns:
        Dictionary mapping IP addresses to their unblock timestamps
    """
    current_time = time.time()
    with dos_lock:
        # Clean up expired blocks first
        expired_ips = [blocked_ip for blocked_ip, expiry in dos_blocked_ips.items()
                      if current_time > expiry]
        for blocked_ip in expired_ips:
            del dos_blocked_ips[blocked_ip]

        # Return copy of current blocked IPs
        return dos_blocked_ips.copy()

def get_dos_stats() -> dict[str, Any]:
    """
    Get DOS protection statistics.

    Returns:
        Dictionary with DOS protection statistics
    """
    current_time = time.time()
    with dos_lock:
        # Clean up old request history
        total_tracked_ips = len(dos_ip_requests)
        active_requests = 0

        for requests in dos_ip_requests.values():
            # Count recent requests (within window)
            recent_requests = [req_time for req_time in requests
                             if current_time - req_time < DOS_WINDOW_SIZE]
            active_requests += len(recent_requests)

        blocked_count = len(dos_blocked_ips)

        # Count total WebSocket connections
        total_ws_connections = sum(len(conns) for conns in ws_connections.values())

        # WebSocket DOS stats
        with ws_dos_lock:
            ws_tracked_sockets = len(ws_dos_violations)
            ws_total_violations = sum(ws_dos_violations.values())

        return {
            'tracked_ips': total_tracked_ips,
            'active_requests_in_window': active_requests,
            'blocked_ips': blocked_count,
            'total_websocket_connections': total_ws_connections,
            'ws_tracked_sockets': ws_tracked_sockets,
            'ws_total_violations': ws_total_violations,
            'window_size_seconds': DOS_WINDOW_SIZE,
            'max_requests_per_window': DOS_MAX_REQUESTS,
            'block_duration_seconds': DOS_BLOCK_DURATION,
            'max_websocket_connections_per_ip': DOS_WEBSOCKET_MAX_CONNECTIONS,
            'ws_max_messages_per_second': DOS_WS_MAX_MESSAGES_PER_SECOND,
            'ws_min_message_interval': DOS_WS_MIN_MESSAGE_INTERVAL,
            'ws_max_violations': DOS_WS_MAX_VIOLATIONS
        }

def _cleanup_websocket_dos_tracking(sock: socket.socket):
    """Clean up DOS tracking for a closed WebSocket."""
    with ws_dos_lock:
        if sock in ws_dos_violations:
            del ws_dos_violations[sock]
        if sock in ws_last_message:
            del ws_last_message[sock]
        if sock in ws_messages_per_second:
            del ws_messages_per_second[sock]

def _check_websocket_dos_protection(sock: socket.socket) -> bool:
    """
    Check WebSocket DOS protection for a specific socket.

    Args:
        sock: WebSocket socket to check

    Returns:
        True if should disconnect due to DOS protection, False if allowed
    """
    current_time = time.time()

    # Get client IP for additional blocking
    try:
        client_addr = sock.getpeername()
        client_ip = client_addr[0] if client_addr else 'unknown'
    except Exception:
        client_ip = 'unknown'

    # Check if IP is globally blocked
    if is_ip_blocked(client_ip):
        log(f"WebSocket message blocked: IP {client_ip} is globally blocked", "WARNING")
        return True

    with ws_dos_lock:
        # Initialize tracking for new sockets
        if sock not in ws_dos_violations:
            ws_dos_violations[sock] = 0
        if sock not in ws_last_message:
            ws_last_message[sock] = 0.0
        if sock not in ws_messages_per_second:
            ws_messages_per_second[sock] = (current_time, 0)

        # Check message frequency (messages per second)
        second_start, message_count = ws_messages_per_second[sock]
        if current_time - second_start >= 1.0:
            # Reset counter every second
            ws_messages_per_second[sock] = (current_time, 1)
        else:
            # Increment message count
            message_count += 1
            ws_messages_per_second[sock] = (second_start, message_count)

            # Check if exceeding messages per second limit
            if message_count > DOS_WS_MAX_MESSAGES_PER_SECOND:
                ws_dos_violations[sock] += 1
                log(f"WebSocket DOS: {client_ip} exceeded {DOS_WS_MAX_MESSAGES_PER_SECOND} messages/second (violation #{ws_dos_violations[sock]})", "WARNING")

                if ws_dos_violations[sock] >= DOS_WS_MAX_VIOLATIONS:
                    log(f"WebSocket DOS: disconnecting {client_ip} after {ws_dos_violations[sock]} violations", "ERROR")
                    # Also trigger IP-level DOS protection
                    check_dos_protection(client_ip)
                    return True
                return False  # Just warn, don't disconnect yet

        # Check minimum interval between messages
        last_time = ws_last_message[sock]
        if last_time > 0 and (current_time - last_time) < DOS_WS_MIN_MESSAGE_INTERVAL:
            ws_dos_violations[sock] += 1
            log(f"WebSocket DOS: {client_ip} messages too frequent, {current_time - last_time:.3f}s interval (violation #{ws_dos_violations[sock]})", "WARNING")

            if ws_dos_violations[sock] >= DOS_WS_MAX_VIOLATIONS:
                log(f"WebSocket DOS: disconnecting {client_ip} for rapid-fire messages", "ERROR")
                check_dos_protection(client_ip)
                return True
            return False  # Just warn, don't disconnect yet

        # Update last message time
        ws_last_message[sock] = current_time

        # Reduce violation count on good behavior (every 10 good messages)
        if ws_dos_violations[sock] > 0 and message_count <= 3 and int(current_time) % 10 == 0:
            ws_dos_violations[sock] = max(0, ws_dos_violations[sock] - 1)

    return False  # Allow message

# Handlers
async def _handle_request(method: str, path: str, version: str, raw_headers: str, body: str = '', client_ip: str = '') -> bytes:
    if version != 'HTTP/1.1':
        return b'HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n'

    # DOS Protection - check if IP is blocked
    if is_ip_blocked(client_ip):
        return b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nIP temporarily blocked due to suspicious activity'

    # DOS Protection - check for abuse
    if check_dos_protection(client_ip):
        return b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nToo many requests - IP blocked temporarily'

    path, params = path.split('?', 1) if '?' in path else (path, '')
    path = await url_decode(path)
    headers = await _parse_headers(raw_headers)
    params = await _parse_params(params)

    # Update request context
    req = _get_request()
    req.headers = headers
    req.params = params
    req.cookies = await _parse_cookies(headers.get('Cookie', ''))
    req.path = path
    req.method = method.upper()
    req.body = body
    req.client_ip = client_ip

    # Iter routes
    for route_path, route_method, func in routes:
        # Only handle non-WebSocket routes here
        if route_method == method.upper() and route_method != 'ws':
            path_vars = await _match_route(path, route_path)
            if path_vars is not None:
                try:
                    out = await func(**path_vars)
                finally:
                    # Reset request context after handler (but keep response context for now)
                    req.headers = {}
                    req.params = {}
                    req.cookies = {}
                    req.path = ''
                    req.method = ''
                    if hasattr(req, 'body'):
                        del req.body

                if isinstance(out, tuple) and len(out) == 2:
                    status_code, content = out
                    # Check for error handler
                    handler = errors.get(status_code) or errors.get(None)
                    if handler:
                        # If handler is for all errors, pass status_code as argument
                        if None in errors and handler == errors[None]:
                            out = await handler(status_code)
                        else:
                            out = await handler()
                        if isinstance(out, tuple) and len(out) == 2:
                            status_code, content = out
                        else:
                            content = out

                        # Determine content type and serialize content for error handler
                        if isinstance(content, (dict, list)):
                            content = json.dumps(content).encode()
                            content_type = 'application/json'
                        elif isinstance(content, str):
                            content = content.encode()
                            content_type = 'text/html'
                        elif isinstance(content, bytes):
                            content_type = 'text/html'
                        else:
                            content = str(content).encode()
                            content_type = 'text/html'

                        header = await _build_response(status_code, content_type)

                        # Reset response context after building response
                        _response_ctx.response = Response()
                        return header + content
                else:
                    content = out

                # Determine content type and serialize content
                if isinstance(content, (dict, list)):
                    # Serialize dict/list to proper JSON
                    content = json.dumps(content).encode()
                    content_type = 'application/json'
                elif isinstance(content, str):
                    content = content.encode()
                    content_type = 'text/html'
                elif isinstance(content, bytes):
                    content_type = 'text/html'
                else:
                    content = str(content).encode()
                    content_type = 'text/html'

                header = await _build_response(200, content_type)

                # Reset response context after building response
                _response_ctx.response = Response()
                return header + content

    # 404 Not Found
    status_code = 404
    handler = errors.get(status_code) or errors.get(None)
    if handler:
        if None in errors and handler == errors[None]:
            out = await handler(status_code)
        else:
            out = await handler()
        if isinstance(out, tuple) and len(out) == 2:
            status_code, content = out
        else:
            content = out

        # Determine content type and serialize content
        if isinstance(content, (dict, list)):
            # Serialize dict/list to proper JSON
            content = json.dumps(content).encode()
            content_type = 'application/json'
        elif isinstance(content, str):
            content = content.encode()
            content_type = 'text/html'
        elif isinstance(content, bytes):
            content_type = 'text/html'
        else:
            content = str(content).encode()
            content_type = 'text/html'

        header = await _build_response(status_code, content_type)

        # Reset response context after building response
        _response_ctx.response = Response()
        return header + content

    return b'HTTP/1.1 404 Not Found\r\n\r\n'

# Socket Handler
async def _csHandler(cs: socket.socket, addr: tuple[str, int]):  # pragma: no cover
    cs.setblocking(False)  # Make client socket non-blocking for async operation
    try:
        request_data = await _receive_request(cs)
        if not request_data:
            return

        method, path, version, headers_str, body = await _parse_http_request(request_data)
        log_request(method, path)

        if await _is_websocket_request(method, request_data):
            await _handle_websocket(cs, path, request_data)
        else:
            await _handle_http_request(cs, method, path, version, headers_str, body, addr)

    except Exception as e:
        log(f"Error handling request: {e}", "ERROR")
    finally:
        cs.close()

# Request handling
async def _receive_request(cs: socket.socket) -> bytes:  # pragma: no cover
    """Receive complete HTTP request data."""
    loop = asyncio.get_event_loop()
    data = b''
    while True:
        try:
            chunk = await loop.sock_recv(cs, 4096)
            if chunk == b'':
                break

            data += chunk
            if len(chunk) < 4096:
                break

        except Exception:
            break
    return data

async def _parse_http_request(data: bytes) -> tuple[str, str, str, str, str]:  # pragma: no cover
    """Parse HTTP request into components."""
    header_split = data.split(b'\r\n\r\n', 1)
    headers_part = header_split[0]
    body_bytes = header_split[1] if len(header_split) == 2 else b''

    headers_lines = headers_part.split(b'\r\n')
    request_line = headers_lines[0].decode(errors='ignore')
    headers_str = b'\r\n'.join(headers_lines[1:]).decode(errors='ignore')

    method, path, version = request_line.split(' ', 2)
    method = method.strip().upper()

    # Handle request body for POST/PUT/PATCH
    if method in ('POST', 'PUT', 'PATCH'):
        body_bytes = await _read_request_body(headers_str, body_bytes)

    body = body_bytes.decode(errors='ignore')
    return method, path, version, headers_str, body

async def _read_request_body(headers_str: str, initial_body: bytes) -> bytes:
    """Read complete request body based on Content-Length."""
    content_length = 0
    for line in headers_str.split('\r\n'):
        if line.lower().startswith('content-length:'):
            try:
                content_length = int(line.split(':', 1)[1].strip())
                break
            except (ValueError, IndexError):
                pass

    # Return initial body if it's already complete
    if len(initial_body) >= content_length:
        return initial_body[:content_length]

    return initial_body

async def _parse_headers_bytes(data: bytes) -> dict[bytes, bytes]:
    """Parse HTTP headers from raw bytes."""
    headers_lines = data.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]
    header_dict: dict[bytes, bytes] = {}

    for line in headers_lines:
        if b':' in line:
            key, value = line.split(b':', 1)
            header_dict[key.strip().lower()] = value.strip()

    return header_dict

async def _handle_http_request(cs: socket.socket, method: str, path: str,
                        version: str, headers_str: str, body: str, addr: tuple[str, int]):
    """Handle regular HTTP request."""
    loop = asyncio.get_event_loop()
    client_ip = addr[0]  # Extract IP from address tuple
    response = await _handle_request(method, path, version, headers_str, body, client_ip)
    await loop.sock_sendall(cs, response)

async def _match_route(request_path: str, route_path: str) -> dict[str, str] | None:
    req_parts = request_path.strip('/').split('/')
    route_parts = route_path.strip('/').split('/')
    if len(req_parts) != len(route_parts):
        return None

    path_vars: dict[str, str] = {}

    for req, route in zip(req_parts, route_parts):
        if route.startswith('<') and route.endswith('>'):
            path_vars[route[1:-1]] = req
        elif req != route:
            return None

    return path_vars

async def _build_response(status_code: int, content_type: str = 'text/html') -> bytes:
    """Build HTTP response header with cookies"""
    resp = _get_response()
    status_text = await get_error_shorthand(status_code)

    header_lines = [
        f'HTTP/1.1 {status_code} {status_text}',
        f'Content-Type: {content_type}'
    ]

    # Add cookie headers
    cookie_headers = resp.get_cookie_headers()
    log(f'Response has {len(resp.cookies)} cookies', 'DEBUG')  # Debug output
    log(f'Cookie headers generated: {cookie_headers}', 'DEBUG')  # Debug output
    for cookie_header in cookie_headers:
        header_lines.append(f'Set-Cookie: {cookie_header}')
        log(f'Adding Set-Cookie header: {cookie_header}', 'DEBUG')  # Debug output

    header_str = '\r\n'.join(header_lines) + '\r\n\r\n'
    return header_str.encode()

# WebSocket handling
async def _is_websocket_request(method: str, data: bytes) -> bool:
    """Check if request is a WebSocket upgrade request."""
    if method != 'GET':
        return False

    headers = await _parse_headers_bytes(data)
    return headers.get(b'upgrade', b'').lower() == b'websocket'

async def _handle_websocket(cs: socket.socket, path: str, data: bytes):  # pragma: no cover
    """Handle WebSocket upgrade and connection."""
    # Get client IP for DOS protection
    try:
        client_addr = cs.getpeername()
        client_ip = client_addr[0] if client_addr else 'unknown'
    except Exception:
        client_ip = 'unknown'

    # DOS Protection - check if IP is blocked
    if is_ip_blocked(client_ip):
        loop = asyncio.get_event_loop()
        await loop.sock_sendall(cs, b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nIP temporarily blocked')
        return

    # DOS Protection - check WebSocket connection limit
    current_connections = count_websocket_connections(client_ip)
    if current_connections >= DOS_WEBSOCKET_MAX_CONNECTIONS:
        loop = asyncio.get_event_loop()
        await loop.sock_sendall(cs, b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nToo many WebSocket connections from your IP')
        log(f"WebSocket connection rejected: IP {client_ip} has {current_connections} connections (limit: {DOS_WEBSOCKET_MAX_CONNECTIONS})", "WARNING")
        return

    # DOS Protection - check for general abuse
    if check_dos_protection(client_ip):
        loop = asyncio.get_event_loop()
        await loop.sock_sendall(cs, b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nToo many requests - IP blocked temporarily')
        return

    # Find matching WebSocket route
    for route_path, route_method, func in routes:
        if route_method == 'ws' and await _match_route(path, route_path) is not None:
            await _perform_websocket_handshake(cs, data)

            # Add connection to ws_connections for this route
            if route_path not in ws_connections:
                ws_connections[route_path] = []
            ws_connections[route_path].append(cs)
            log(f"WebSocket connected from {client_ip} to {route_path}, total: {len(ws_connections[route_path])}", "DEBUG")

            try:
                await func(cs)
            finally:
                # Clean up WebSocket DOS tracking
                _cleanup_websocket_dos_tracking(cs)

                # Remove connection when handler finishes
                if route_path in ws_connections and cs in ws_connections[route_path]:
                    ws_connections[route_path].remove(cs)
                    log(f"WebSocket disconnected from {client_ip} ({route_path}), remaining: {len(ws_connections[route_path])}", "DEBUG")
                    # Clean up empty route entries
                    if not ws_connections[route_path]:
                        del ws_connections[route_path]
            return

    # No matching WebSocket route found
    loop = asyncio.get_event_loop()
    await loop.sock_sendall(cs, b'HTTP/1.1 404 Not Found\r\n\r\n')

async def _perform_websocket_handshake(cs: socket.socket, data: bytes):  # pragma: no cover
    """Perform WebSocket handshake."""
    import base64
    import hashlib

    loop = asyncio.get_event_loop()
    headers = await _parse_headers_bytes(data)
    key = headers.get(b'sec-websocket-key', b'')

    accept_key = base64.b64encode(
        hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
    )

    handshake_response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_key + b"\r\n\r\n"
    )

    await loop.sock_sendall(cs, handshake_response)

# Main loop
async def _serve(ip:str, port:int):  # pragma: no cover - server main loop
    s.bind((ip, port))
    s.listen(5)
    s.setblocking(False)  # Make socket non-blocking for async operation

    loop = asyncio.get_event_loop()

    log(f"Server started on http://{ip}:{port}", "INFO")

    while True:
        try:
            cs, addr = await loop.sock_accept(s)
            asyncio.create_task(_csHandler(cs, addr))
        except Exception as e:
            log(f"Error accepting connection: {e}", "ERROR")
            await asyncio.sleep(0.1)

def serve(ip: str, port: int = 8080):
    """
    Start the HTTP server on the specified IP address and port.

    Runs the asyncio event loop and starts accepting HTTP and WebSocket connections.
    The server will handle requests until interrupted (Ctrl+C) or an error occurs.

    Args:
        ip: IP address to bind to (e.g., 'localhost', '0.0.0.0')
        port: Port number to listen on. Defaults to 8080.

    Example:
        ```python
        import http_server as app

        @app.route('/')
        async def home():
            return "Hello World!"

        # Start server on localhost:8080
        app.serve('localhost')

        # Start server on all interfaces, port 3000
        app.serve('0.0.0.0', 3000)
        ```
    """
    try: asyncio.run(_serve(ip, port))
    except KeyboardInterrupt:
        log('Server stopped')
    except Exception:
        log(f'{format_exc()}', "ERROR")

# Content
async def template(filename: str, **kwargs: Any) -> str | tuple[int, str]:
    """
    Load and render a template file with variable substitution.

    Loads a file from the static directory and replaces template variables in the format
    {{ variable_name }} with provided values. Returns 404 if file not found.

    Args:
        filename: Template filename (automatically prefixed with static/ if needed)
        **kwargs: Variables to substitute in the template

    Returns:
        Rendered template string, or (404, error_message) tuple if file not found

    Example:
        ```python
        @route('/user/<username>')
        async def user_profile(username):
            return await template('profile.html',
                                username=username,
                                login_time="2023-01-01")

        # In profile.html:
        # <h1>Welcome {{ username }}!</h1>
        # <p>Last login: {{ login_time }}</p>
        ```
    """
    filename = await _normalize_path(filename)

    if not os.path.exists(filename) or not os.path.isfile(filename):
        return 404, '404 File not found'

    with open(filename, 'r', encoding='utf-8') as f:
        template = f.read()

    for key, value in kwargs.items():
        template = template.replace(f'{{{{ {key} }}}}', str(value))
    return template

async def redirect(url: str) -> tuple[int, str]:
    """
    Create a 302 redirect response to the specified URL.

    Returns a redirect response that will cause the browser to navigate to the new URL.
    Uses meta refresh for browser compatibility.

    Args:
        url: URL to redirect to (can be relative or absolute)

    Returns:
        Tuple of (302, redirect_html)

    Example:
        ```python
        @route('/old-page')
        async def old_page():
            return await redirect('/new-page')

        @route('/login')
        async def login():
            # Redirect to external site
            return await redirect('https://example.com/auth')
        ```
    """
    html = f'<meta http-equiv="refresh" content="0;url={url}">'
    # The Location header will be added by the server logic for 3xx codes, but include it in the body for clarity
    return 302, html

# Websockets
async def ws_send(sock: socket.socket, message: str):  # pragma: no cover
    """
    Send a text message to a WebSocket client.

    Formats the message as a proper WebSocket frame and sends it to the specified socket.
    Handles frame formatting including payload length encoding.

    Args:
        sock: WebSocket client socket
        message: Text message to send

    Example:
        ```python
        @route('/ws/chat', 'ws')
        async def chat_handler(sock):
            await ws_send(sock, "Welcome to the chat!")

            while True:
                data = await ws_recv(sock)
                if not data:
                    break
                await ws_send(sock, f"Echo: {data}")
        ```
    """
    # Send a text frame (opcode 0x1)
    loop = asyncio.get_event_loop()
    payload = message.encode('utf-8')
    frame = bytearray()
    frame.append(0x81)  # FIN + text frame
    length = len(payload)
    if length < 126:
        frame.append(length)
    elif length < (1 << 16):
        frame.append(126)
        frame += length.to_bytes(2, 'big')
    else:
        frame.append(127)
        frame += length.to_bytes(8, 'big')
    frame += payload
    await loop.sock_sendall(sock, frame)

async def ws_recv(sock: socket.socket) -> str:  # pragma: no cover
    """
    Receive a text message from a WebSocket client.

    Reads and decodes a WebSocket frame from the client. Handles both masked (client->server)
    and unmasked frames, and supports extended payload lengths.

    Includes built-in DOS protection that automatically disconnects clients sending too many
    messages or messages too frequently.

    Args:
        sock: WebSocket client socket

    Returns:
        Decoded text message, or empty string if connection closed, error occurred, or DOS protection triggered

    Example:
        ```python
        @route('/ws/echo', 'ws')
        async def echo_handler(sock):
            while True:
                message = await ws_recv(sock)
                if not message:  # Connection closed or DOS protection
                    break
                await ws_send(sock, f"Echo: {message}")
        ```
    """
    # DOS Protection - check before processing message
    should_disconnect = _check_websocket_dos_protection(sock)
    if should_disconnect:
        # Clean up tracking and return empty string to signal disconnection
        _cleanup_websocket_dos_tracking(sock)
        return ''

    # Receive a text frame (no fragmentation, no mask)
    loop = asyncio.get_event_loop()
    try:
        first2 = await loop.sock_recv(sock, 2)
        if not first2 or len(first2) < 2:
            # Connection closed - clean up DOS tracking
            _cleanup_websocket_dos_tracking(sock)
            return ''
        fin_opcode, length = first2
        if (fin_opcode & 0x0F) != 0x1:
            return ''  # Only text frames
        if length & 0x80:
            # Masked (client to server)
            mask_len = length & 0x7F
            if mask_len == 126:
                ext = await loop.sock_recv(sock, 2)
                mask_len = int.from_bytes(ext, 'big')
            elif mask_len == 127:
                ext = await loop.sock_recv(sock, 8)
                mask_len = int.from_bytes(ext, 'big')
            mask = await loop.sock_recv(sock, 4)
            payload = bytearray()
            for i in range(mask_len):
                byte_data = await loop.sock_recv(sock, 1)
                if not byte_data:
                    break
                payload.append(byte_data[0] ^ mask[i % 4])
        else:
            # Not masked (server to client)
            if length == 126:
                ext = await loop.sock_recv(sock, 2)
                length = int.from_bytes(ext, 'big')
            elif length == 127:
                ext = await loop.sock_recv(sock, 8)
                length = int.from_bytes(ext, 'big')
            payload = await loop.sock_recv(sock, length)
        return payload.decode('utf-8')
    except Exception:
        # Connection error - clean up DOS tracking
        _cleanup_websocket_dos_tracking(sock)
        return ''

async def ws_broadcast(route: str, data: str):
    """
    Broadcast a message to all connected WebSocket clients on a specific route.

    Sends the same message to all active WebSocket connections for the specified route.
    Automatically handles disconnected clients and cleans up the connection list.

    Args:
        route: WebSocket route path (e.g., '/ws/chat')
        data: Message to broadcast to all clients

    Example:
        ```python
        # In a WebSocket handler
        @route('/ws/chat', 'ws')
        async def chat_handler(sock):
            username = await ws_recv(sock)
            await ws_broadcast('/ws/chat', f"{username} joined the chat")

            while True:
                message = await ws_recv(sock)
                if not message:
                    break
                # Broadcast to all connected clients
                await ws_broadcast('/ws/chat', f"{username}: {message}")

        # From any other function
        async def notify_all():
            await ws_broadcast('/ws/notifications', "Server maintenance in 5 minutes")
        ```
    """
    if route not in ws_connections:
        log(f"No connections found for route: {route}", "DEBUG")
        return

    # Create a copy of the connections list to avoid modification during iteration
    connections: list[socket.socket] = ws_connections[route].copy()
    disconnected: list[socket.socket] = []

    for sock in connections:
        try:
            await ws_send(sock, data)
        except Exception as e:
            log(f"Error sending to WebSocket client: {e}", "DEBUG")
            disconnected.append(sock)

    # Remove disconnected sockets
    for sock in disconnected:
        if route in ws_connections and sock in ws_connections[route]:
            ws_connections[route].remove(sock)
            log(f"Removed disconnected WebSocket from {route}", "DEBUG")

    # Clean up empty route entries
    if route in ws_connections and not ws_connections[route]:
        del ws_connections[route]
        log(f"Cleaned up empty WebSocket route: {route}", "DEBUG")

# Password & login utils
def _hash(password: str, iterations: int = 100_000) -> bytes:
    salt = b'\xc2\x10\x9c\xa1S?\xc4\xd1{H\x86\x9dD\xdd\x8f\xc2'
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

def _check(password: str, stored_hash: bytes, iterations: int = 100_000) -> bool:
    salt = b'\xc2\x10\x9c\xa1S?\xc4\xd1{H\x86\x9dD\xdd\x8f\xc2'
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return hmac.compare_digest(new_hash, stored_hash)

def _gen_token() -> str:
    """Generate a simple session token"""
    data = f"{time.time()}:{os.urandom(4)}"
    return hashlib.sha256(data.encode()).hexdigest()

# Login management
def create_user(username: str, password: str) -> bool:
    """
    Create a new user with the given username and password.
    Args:
        username (str): The username for the new user account
        password (str): The plain text password for the new user account
    Returns:
        bool: True if the user was successfully created, False if the username already exists
    Note:
        The password is automatically hashed before being stored for security purposes.
    """
    if username in users:
        return False  # User already exists

    hashed_psw = _hash(password)
    users[username] = hashed_psw
    return True

def delete_user(username: str) -> bool:
    """
    Delete a user from the users collection.
    Args:
        username (str): The username of the user to delete.
    Returns:
        bool: True if the user was successfully deleted, False if the user does not exist.
    """
    if username not in users:
        return False  # User does not exist

    del users[username]
    return True

def edit_user(username: str, new_password: str) -> bool:
    """
    Edit an existing user's password.
    Args:
        username (str): The username of the user to edit.
        new_password (str): The new password to set for the user.
    Returns:
        bool: True if the user was successfully updated, False if the user does not exist.
    """
    if username not in users:
        return False  # User does not exist

    users[username] = _hash(new_password)
    return True

def login(username: str, password: str) -> bool:
    """
    Authenticate a user with their username and password.
    Args:
        username (str): The username to authenticate
        password (str): The password to verify against the stored user credentials
    Returns:
        bool: True if authentication is successful, False if the user doesn't exist
              or the password is incorrect
    Raises:
        None: This function handles errors by returning False rather than raising exceptions
    """
    if username not in users:
        return False  # User does not exist

    return _check(password, users[username])

# Profile management
def get_user_profile(username: str) -> dict[str, Any] | None:
    """
    Get a user's profile information.
    Args:
        username (str): The username to get the profile for
    Returns:
        dict[str, Any] | None: User profile dict with 'username' and 'bio', or None if user doesn't exist
    """
    if username not in users:
        return None

    return profiles.get(username, {'username': username, 'bio': ''})

def update_user_profile(username: str, bio: str) -> bool:
    """
    Update a user's profile bio.
    Args:
        username (str): The username to update
        bio (str): The new bio text
    Returns:
        bool: True if successful, False if user doesn't exist
    """
    if username not in users:
        return False

    if username not in profiles:
        profiles[username] = {'username': username, 'bio': ''}

    profiles[username]['bio'] = bio
    return True

def change_username(old_username: str, new_username: str) -> str:
    """
    Change a user's username.
    Args:
        old_username (str): Current username
        new_username (str): New username
    Returns:
        str: 'success' if changed, 'exists' if new username exists, 'failed' if old user doesn't exist
    """
    if old_username not in users:
        return 'failed'

    if new_username in users:
        return 'exists'

    # Move user data
    users[new_username] = users[old_username]
    del users[old_username]

    # Move profile data if it exists
    if old_username in profiles:
        profiles[new_username] = profiles[old_username]
        profiles[new_username]['username'] = new_username
        del profiles[old_username]

    return 'success'

def user_exists(username: str) -> bool:
    """
    Check if a user exists in the database.
    Args:
        username (str): The username to check
    Returns:
        bool: True if user exists, False otherwise
    """
    return username in users

def save_users(path:str) -> bool:
    """
    Save the current user database and profiles to a file.

    Serializes the users dictionary and profiles dictionary to a JSON file at the specified path.
    Returns True if successful, False if an error occurs.

    Args:
        path: File path to save the user database

    Example:
        ```python
        save_users('users.json')
        ```
    """
    try:
        # Convert bytes to base64 strings for JSON serialization
        serializable_users = {}
        for username, hashed_password in users.items():
            if isinstance(hashed_password, bytes):
                import base64
                serializable_users[username] = base64.b64encode(hashed_password).decode('utf-8')
            else:
                serializable_users[username] = hashed_password

        # Prepare data structure with both users and profiles
        data:dict[str, Any] = {
            'users': serializable_users,
            'profiles': profiles
        }

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        log(f"Error saving users and profiles: {e}", "ERROR")
        return False

def load_users(path:str) -> bool:
    """
    Load the user database and profiles from a file.

    Deserializes the users dictionary and profiles dictionary from a JSON file at the specified path.
    Returns True if successful, False if an error occurs.

    Args:
        path: File path to load the user database from

    Example:
        ```python
        load_users('users.json')
        ```
    """
    try:
        with open(path, 'r') as f:
            data:dict[str, Any] = json.load(f)

        # New format with users and profiles
        loaded_users = data.get('users', {})
        loaded_profiles = data.get('profiles', {})

        # Clear existing data
        users.clear()
        profiles.clear()

        # Load users - Convert base64 strings back to bytes
        for username, hashed_password in loaded_users.items():
            if isinstance(hashed_password, str):
                try:
                    # Try to decode as base64, assuming it's a hashed password
                    users[username] = base64.b64decode(hashed_password.encode('utf-8'))
                except Exception:
                    # If decoding fails, skip this entry or encode as bytes for backward compatibility
                    log(f"Warning: Could not decode password hash for user '{username}', skipping", "WARNING")
                    continue
            elif isinstance(hashed_password, bytes):
                users[username] = hashed_password
            else:
                # Skip invalid entries
                log(f"Warning: Invalid password hash type for user '{username}', skipping", "WARNING")
                continue

        # Load profiles
        for username, profile_data in loaded_profiles.items():
            if isinstance(profile_data, dict):
                profiles[username] = profile_data
            else:
                log(f"Warning: Invalid profile data for user '{username}', skipping", "WARNING")

        log(f"Loaded {len(users)} users, {len(profiles)} profiles", "INFO")
        return True
    except FileNotFoundError:
        log(f"User database file '{path}' not found. Starting with empty database.", "INFO")
        return True
    except Exception as e:
        log(f"Error loading users and profiles: {e}", "ERROR")
        return False

# Session management
def verify_session(token: str) -> bool:
    """Verify if a session token is valid"""
    return token in sessions

def get_username(token: str) -> str:
    """Get username from session token"""
    return sessions.get(token, {}).get('username', '')

def start_session(username: str) -> str:
    """Create a new session for user"""
    token = _gen_token()
    sessions[token] = {
        'username': username,
        'created': time.time()
    }
    return token

def end_session(token: str) -> None:
    """Delete a session"""
    if token in sessions:
        del sessions[token]

# Cookies
def set_cookie(name: str, value: str, path: str = '/', domain: str = '',
               expires: str = '', max_age: int = 0, secure: bool = False,
               httponly: bool = False, samesite: str = ''):
    """
    Set a cookie in the current HTTP response.

    Sets a cookie that will be sent to the client in the response headers.
    Must be called during request handling before the response is sent.

    Args:
        name: Cookie name
        value: Cookie value
        path: Path scope for the cookie. Defaults to '/'
        domain: Domain scope for the cookie
        expires: Expiration date string (e.g., 'Thu, 01 Jan 1970 00:00:00 GMT')
        max_age: Max age in seconds (takes precedence over expires)
        secure: If True, cookie only sent over HTTPS
        httponly: If True, cookie not accessible via JavaScript
        samesite: SameSite policy ('Strict', 'Lax', or 'None')

    Example:
        ```python
        @route('/login', 'POST')
        async def login():
            # Set a session cookie
            set_cookie('session_id', 'abc123', httponly=True, secure=True)

            # Set a preference cookie that expires in 30 days
            set_cookie('theme', 'dark', max_age=30*24*3600)

            return "Logged in successfully"
        ```
    """
    resp = _get_response()
    log(f'Setting cookie: {name}={value} (max_age={max_age})', 'DEBUG')  # Debug output
    resp.set_cookie(name, value, path=path, domain=domain, expires=expires,
                   max_age=max_age, secure=secure, httponly=httponly, samesite=samesite)
    log(f'Cookie added to response. Total cookies: {len(resp.cookies)}', 'DEBUG')  # Debug output

def get_cookie(name: str, default: str = '') -> str:
    """
    Get a cookie value from the current HTTP request.

    Retrieves a cookie value that was sent by the client in the request headers.

    Args:
        name: Cookie name to retrieve
        default: Default value if cookie not found. Defaults to empty string.

    Returns:
        Cookie value or default if not found

    Example:
        ```python
        @route('/dashboard')
        async def dashboard():
            session_id = get_cookie('session_id')
            theme = get_cookie('theme', 'light')  # Default to 'light'

            if not session_id:
                return await redirect('/login')

            return f"Welcome! Theme: {theme}"
        ```
    """
    req = _get_request()
    return req.cookies.get(name, default)

def delete_cookie(name: str, path: str = '/'):
    """
    Delete a cookie by setting it to expire immediately.

    Instructs the client to delete the specified cookie by setting its expiration
    date to the past. The path must match the original cookie's path.

    Args:
        name: Cookie name to delete
        path: Path scope of the cookie to delete. Must match original path.

    Example:
        ```python
        @route('/logout')
        async def logout():
            delete_cookie('session_id')
            delete_cookie('remember_me', path='/auth')
            return "Logged out successfully"
        ```
    """
    resp = _get_response()
    resp.delete_cookie(name, path)

# Decorators
def route(path: str, method: str = 'GET') -> Callable[[RouteHandler], RouteHandler]:
    """
    Decorator to register a route handler for specific HTTP paths and methods.

    Registers a function to handle HTTP requests to the specified path and method.
    Supports path variables in the format <variable_name>.

    Args:
        path: URL path pattern (e.g., '/', '/api/users', '/user/<id>')
        method: HTTP method ('GET', 'POST', 'PUT', 'DELETE', 'ws' for WebSocket)

    Returns:
        Decorator function

    Example:
        ```python
        @route('/')
        async def home():
            return "Welcome home!"

        @route('/api/users', 'POST')
        async def create_user():
            return "User created"

        @route('/user/<user_id>')
        async def get_user(user_id):
            return f"User: {user_id}"

        @route('/ws/chat', 'ws')
        async def chat_handler(sock):
            # WebSocket handler
            while True:
                data = await ws_recv(sock)
                if not data:
                    break
                await ws_send(sock, f"Echo: {data}")
        ```
    """
    def decorator(func: RouteHandler):
        routes.append((path, method, func))
        return func
    return decorator

def error(err_code: int | None = None):
    """
    Decorator to register an error handler for specific HTTP status codes.

    Registers a function to handle specific HTTP error codes or all errors.
    Error handlers receive the status code as a parameter if err_code is None.

    Args:
        err_code: HTTP status code to handle (404, 500, etc.) or None for all errors

    Returns:
        Decorator function

    Example:
        ```python
        @error(404)
        async def not_found():
            return await template('404.html')

        @error(500)
        async def server_error():
            return "Internal server error occurred"

        @error()  # Handle all errors
        async def handle_all_errors(status_code):
            if status_code == 403:
                return "Access denied"
            return f"Error {status_code} occurred"
        ```
    """
    def decorator(func: ErrorHandler):
        errors[err_code] = func
        return func
    return decorator

@overload
def ratelimit(num_req: Union[int, float], reset_interval: Union[int, float] = -1) -> Callable[[F], F]:
    """
    Rate limiting decorator for HTTP routes and WebSocket endpoints.

    Applies rate limiting to route handlers to prevent abuse and control request frequency.

    Args:
        num_req: For delay-based (reset_interval=-1): delay in seconds between requests.
                For count-based (reset_interval>0): maximum number of requests allowed.
        reset_interval: Time window in seconds for count-based limiting, or -1 for delay-based.

    Returns:
        Decorated function with rate limiting applied
    """
    ...

@overload
def ratelimit(sock: socket.socket, delay_seconds: Union[int, float], identifier: str = "") -> bool:
    """
    Check rate limiting for WebSocket data transmission (delay-based).

    Performs delay-based rate limiting check for individual WebSocket messages.
    This is a simplified version where only delay between messages is specified.

    Args:
        sock: WebSocket client socket
        delay_seconds: Minimum delay in seconds between messages (assumes reset_interval = -1)
        identifier: Optional identifier for different rate limit categories

    Returns:
        True if rate limited (should block), False if allowed (can proceed)
    """
    ...

@overload
def ratelimit(sock: socket.socket, rate_params: tuple[Union[int, float], Union[int, float]], identifier: str = "") -> bool:
    """
    Check rate limiting for WebSocket data transmission (full control).

    Performs rate limiting check for individual WebSocket messages or data transmissions.
    Supports both delay-based and count-based rate limiting.

    Args:
        sock: WebSocket client socket
        rate_params: Tuple of (num_req, reset_interval) where:
                    - For delay-based: (delay_seconds, -1)
                    - For count-based: (max_requests, time_window)
        identifier: Optional identifier for different rate limit categories

    Returns:
        True if rate limited (should block), False if allowed (can proceed)
    """
    ...

def ratelimit(*args: Any, **kwargs: Any) -> Union[Callable[[F], F], bool]:
    """Docstrings are in the overloads, dont add one here!"""
    # Parse arguments based on first argument type
    if args and isinstance(args[0], socket.socket):
        # WebSocket function mode: ratelimit(sock, (num_req, reset_interval), identifier="")
        sock = args[0]
        rate_params = args[1] if len(args) > 1 else (1.0, -1)
        identifier = str(args[2]) if len(args) > 2 else str(kwargs.get('identifier', ''))

        # Extract rate limiting parameters with safe type handling
        num_req: float = 1.0
        reset_interval: float = -1.0

        try:
            if hasattr(rate_params, '__len__') and hasattr(rate_params, '__getitem__'):
                # It's a sequence-like object
                if len(rate_params) >= 2:  # type: ignore
                    num_req = float(rate_params[0])  # type: ignore
                    reset_interval = float(rate_params[1])  # type: ignore
                elif len(rate_params) >= 1:  # type: ignore
                    num_req = float(rate_params[0])  # type: ignore
                    reset_interval = -1.0
            else:
                # Handle single numeric value as delay-based
                num_req = float(rate_params)  # type: ignore
                reset_interval = -1.0
        except (ValueError, TypeError, IndexError):
            # Fallback to defaults if anything goes wrong
            num_req = 1.0
            reset_interval = -1.0        # Get client IP from socket
        try:
            client_addr = sock.getpeername()
            client_ip = client_addr[0] if client_addr else 'unknown'
        except Exception:
            client_ip = 'unknown'

        # DOS Protection - check if IP is blocked
        if is_ip_blocked(client_ip):
            log(f"WebSocket data blocked: IP {client_ip} is blocked", "WARNING")
            return True  # Block the data transmission

        # Use socket object as part of the key for WebSocket-specific rate limiting
        rate_key = (sock, identifier or 'ws_data')
        current_time = time.time()

        with rate_limit_lock:
            if reset_interval == -1:
                # Delay-based rate limiting for WebSocket data
                if rate_key in ws_rate_limit_delays:
                    time_since_last = current_time - ws_rate_limit_delays[rate_key]
                    if time_since_last < num_req:
                        # Rate limited - reset the delay
                        ws_rate_limit_delays[rate_key] = current_time
                        remaining_delay = num_req - time_since_last
                        log(f"WebSocket rate limited {client_ip} on {identifier or 'data'}, delay reset. Wait {remaining_delay:.1f}s", "WARNING")
                        return True  # Rate limited

                # Update last request time
                ws_rate_limit_delays[rate_key] = current_time
                return False  # Not rate limited
            else:
                # Count-based rate limiting for WebSocket data
                if rate_key not in ws_rate_limit_counts:
                    ws_rate_limit_counts[rate_key] = []

                # Clean old requests outside the time window
                ws_rate_limit_counts[rate_key] = [
                    req_time for req_time in ws_rate_limit_counts[rate_key]
                    if current_time - req_time < reset_interval
                ]

                # Check if rate limit exceeded
                if len(ws_rate_limit_counts[rate_key]) >= num_req:
                    log(f"WebSocket rate limited {client_ip} on {identifier or 'data'}, {len(ws_rate_limit_counts[rate_key])} requests in {reset_interval}s", "WARNING")
                    return True  # Rate limited

                # Add current request
                ws_rate_limit_counts[rate_key].append(current_time)
                return False  # Not rate limited
    else:
        # Decorator mode: ratelimit(num_req, reset_interval=-1)
        num_req = float(args[0]) if args else 1.0
        reset_interval = float(args[1]) if len(args) > 1 else -1.0

        def decorator(func: F) -> F:
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Get client IP - try to extract from various sources
                client_ip = get_client_ip()

                # DOS Protection - check if IP is blocked (additional layer)
                if is_ip_blocked(client_ip):
                    if 'sock' in str(func.__annotations__.values()):  # WebSocket
                        return
                    else:
                        return 429, "IP temporarily blocked due to suspicious activity"

                # Get route path from request context or function name
                route_path = getattr(_get_request(), 'path', func.__name__)

                rate_key = (client_ip, route_path)
                current_time = time.time()

                with rate_limit_lock:
                    if reset_interval == -1:
                        # Delay-based rate limiting
                        if rate_key in rate_limit_delays:
                            time_since_last = current_time - rate_limit_delays[rate_key]
                            if time_since_last < num_req:
                                # Rate limited - reset the delay
                                rate_limit_delays[rate_key] = current_time
                                remaining_delay = num_req - time_since_last
                                log(f"Rate limited {client_ip} on {route_path}, delay reset. Wait {remaining_delay:.1f}s", "WARNING")

                                # Return rate limit response
                                if 'sock' in str(func.__annotations__.values()):  # WebSocket
                                    # For WebSocket, we can't return an HTTP response, so just close
                                    return
                                else:
                                    return 429, f"Rate limited. Try again in {remaining_delay:.1f} seconds."

                        # Update last request time
                        rate_limit_delays[rate_key] = current_time

                    else:
                        # Count-based rate limiting
                        if rate_key not in rate_limit_counts:
                            rate_limit_counts[rate_key] = []

                        # Clean old requests outside the time window
                        rate_limit_counts[rate_key] = [
                            req_time for req_time in rate_limit_counts[rate_key]
                            if current_time - req_time < reset_interval
                        ]

                        # Check if rate limit exceeded
                        if len(rate_limit_counts[rate_key]) >= num_req:
                            log(f"Rate limited {client_ip} on {route_path}, {len(rate_limit_counts[rate_key])} requests in {reset_interval}s", "WARNING")

                            if 'sock' in str(func.__annotations__.values()):  # WebSocket
                                return
                            else:
                                return 429, f"Rate limited. Max {num_req} requests per {reset_interval} seconds."

                        # Add current request
                        rate_limit_counts[rate_key].append(current_time)

                # Call the original function
                return await func(*args, **kwargs)

            return wrapper  # type: ignore

        return decorator

__all__ = [
    'serve', 'route', 'error', 'ratelimit',
    'template', 'redirect',
    'log',
    'ws_send', 'ws_recv', 'ws_broadcast',
    'request', 'response',
    'set_cookie', 'get_cookie', 'delete_cookie',
    # DOS protection management
    'is_ip_blocked', 'check_dos_protection', 'count_websocket_connections',
    'unblock_ip', 'get_blocked_ips', 'get_dos_stats',
    # DOS protection configuration
    'DOS_WINDOW_SIZE', 'DOS_MAX_REQUESTS', 'DOS_BLOCK_DURATION', 'DOS_WEBSOCKET_MAX_CONNECTIONS',
    'DOS_WS_MAX_MESSAGES_PER_SECOND', 'DOS_WS_MIN_MESSAGE_INTERVAL', 'DOS_WS_MAX_VIOLATIONS'
]
