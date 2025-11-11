from typing import Any
import httplib as app
import json

# Actual html pages
@app.ratelimit(15, 1)
@app.route('/')
async def index() -> Any:
    return await app.template('static/index.html')

@app.ratelimit(15, 1)
@app.route('/login')
async def login_page() -> Any:
    return await app.template('static/login.html')

@app.ratelimit(15, 1)
@app.route('/register')
async def register_page() -> Any:
    return await app.template('static/register.html')

### API ###
# Auth
@app.ratelimit(2, 25)
@app.route('/api/login', method='POST')
async def api_login() -> Any:
    try:
        data = json.loads(app.request.body)
        username = data.get('username', '').strip()
        password = data.get('password', '')

        app.log(f"Login attempt for username: '{username}'", 'DEBUG')

        if not username or not password:
            app.log("Login failed: Missing username or password", 'INFO')
            return {'success': False, 'error': 'Username and password required'}

        result = app.login(username, password)
        app.log(f"Login result for '{username}': {result}", 'DEBUG')

        if result:
            token = app.start_session(username)
            app.log(f"Created session token for '{username}': {token[:10]}...", 'DEBUG')
            app.set_cookie('session', token, max_age=86400)
            app.log(f"Session cookie set for '{username}'", 'DEBUG')
            return {'success': True}
        else:
            app.log(f"Login failed for '{username}': Invalid credentials", 'DEBUG')
            return {'success': False, 'error': 'Invalid username or password'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

@app.ratelimit(2, 10*60)
@app.route('/api/register', method='POST')
async def api_register() -> Any:
    try:
        data = json.loads(app.request.body)
        username = data.get('username', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirmPassword', '')

        app.log(f"Register attempt for username: '{username}'", 'DEBUG')

        if not username or not password:
            app.log("Registration failed: Missing username or password", 'DEBUG')
            return {'success': False, 'error': 'Username and password required'}

        if password != confirm_password:
            app.log("Registration failed: Passwords do not match", 'DEBUG')
            return {'success': False, 'error': 'Passwords do not match'}

        if len(password) < 6:
            app.log("Registration failed: Password too short", 'DEBUG')
            return {'success': False, 'error': 'Password must be at least 6 characters'}

        result = app.create_user(username, password)
        app.log(f"User creation result for '{username}': {result}", 'DEBUG')

        if result:
            token = app.start_session(username)
            app.log(f"Created session token for new user '{username}': {token[:10]}...", 'DEBUG')
            app.set_cookie('session', token, max_age=86400)
            app.log(f"Session cookie set for new user '{username}'", 'DEBUG')
            return {'success': True}
        else:
            app.log(f"Registration failed for '{username}': Username already exists", 'DEBUG')
            return {'success': False, 'error': 'Username already exists'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

@app.ratelimit(10, 5)
@app.route('/api/auth/status')
async def auth_status() -> Any:
    session = app.get_cookie('session')
    app.log(f"Auth status check - session cookie: '{session[:10] if session else 'None'}...'", 'DEBUG')

    if session and app.verify_session(session):
        username = app.get_username(session)
        app.log(f"Auth status: authenticated as '{username}'", 'DEBUG')
        return {'authenticated': True, 'username': username}

    app.log("Auth status: not authenticated", 'DEBUG')
    return {'authenticated': False}

@app.ratelimit(2, 20)
@app.route('/api/logout', method='POST')
async def api_logout() -> Any:
    session = app.get_cookie('session')
    if session:
        app.end_session(session)
    app.delete_cookie('session')
    return {'success': True}

# Preferences
@app.ratelimit(10, 5)
@app.route('/api/theme')
async def get_theme() -> Any:
    # Debug: Show all cookies received
    all_cookies = app.request.cookies
    app.log(f"All cookies received: {all_cookies}", 'DEBUG')

    theme = app.get_cookie('theme')
    app.log(f"Retrieved theme cookie: '{theme}'", 'DEBUG')  # Debug output
    return {'theme': theme or 'dark'}

@app.ratelimit(10, 10)
@app.route('/api/theme', method='POST')
async def set_theme() -> Any:
    try:
        data = json.loads(app.request.body)
        theme = data.get('theme', 'dark')
        app.log(f"Setting theme cookie to: '{theme}'", 'DEBUG')  # Debug output
        if theme in ['light', 'dark']:
            # Try setting cookie with simpler attributes first
            app.set_cookie('theme', theme, path='/', max_age=31536000)  # 1 year
            app.log(f"Cookie set successfully for theme: '{theme}'", 'DEBUG')
            return {'success': True}
        return {'success': False, 'error': 'Invalid theme'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception as e:
        app.log(f"Error setting theme: {str(e)}", 'ERROR')
        return {'success': False, 'error': 'Server error'}

# User profile endpoints
@app.ratelimit(15, 5)
@app.route('/api/profile/<user>')
async def get_user_profile(user: str) -> Any:
    if not user:
        return {'success': False, 'error': 'Username required'}

    profile = app.get_user_profile(user)
    if profile:
        return {'success': True, 'profile': profile}
    else:
        return {'success': False, 'error': 'User not found'}

@app.ratelimit(15, 5)
@app.route('/api/profile', method='GET')
async def get_own_profile() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    username = app.get_username(session)
    profile = app.get_user_profile(username)
    return {'success': True, 'profile': profile}

@app.ratelimit(5, 10)
@app.route('/api/profile', method='POST')
async def update_profile() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    try:
        data = json.loads(app.request.body)
        username = app.get_username(session)
        bio = data.get('bio', '').strip()

        if len(bio) > 500:
            return {'success': False, 'error': 'Bio must be 500 characters or less'}

        result = app.update_user_profile(username, bio)
        if result:
            return {'success': True}
        else:
            return {'success': False, 'error': 'Failed to update profile'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

@app.ratelimit(5, 5*60)
@app.route('/api/account/username', method='POST')
async def change_username() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    try:
        data = json.loads(app.request.body)
        old_username = app.get_username(session)
        new_username = data.get('username', '').strip()

        if not new_username or len(new_username) < 3:
            return {'success': False, 'error': 'Username must be at least 3 characters'}

        if len(new_username) > 20:
            return {'success': False, 'error': 'Username must be 20 characters or less'}

        result = app.change_username(old_username, new_username)
        if result == 'success':
            # Update session with new username
            app.end_session(session)
            token = app.start_session(new_username)
            app.set_cookie('session', token, max_age=86400)
            return {'success': True}
        elif result == 'exists':
            return {'success': False, 'error': 'Username already exists'}
        else:
            return {'success': False, 'error': 'Failed to change username'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

@app.ratelimit(2, 5*60)
@app.route('/api/account/password', method='POST')
async def change_password() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    try:
        data = json.loads(app.request.body)
        username = app.get_username(session)
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return {'success': False, 'error': 'Current and new passwords required'}

        if len(new_password) < 6:
            return {'success': False, 'error': 'New password must be at least 6 characters'}

        # Verify current password
        if not app.login(username, current_password):
            return {'success': False, 'error': 'Current password is incorrect'}

        result = app.edit_user(username, new_password)
        if result:
            return {'success': True}
        else:
            return {'success': False, 'error': 'Failed to change password'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

@app.ratelimit(5, 5*60)
@app.route('/api/account/delete', method='POST')
async def delete_account() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    try:
        data = json.loads(app.request.body)
        username = app.get_username(session)
        password = data.get('password', '')

        if not password:
            return {'success': False, 'error': 'Password required'}

        # Verify password before deletion
        if not app.login(username, password):
            return {'success': False, 'error': 'Invalid password'}

        result = app.delete_user(username)
        if result:
            app.end_session(session)
            app.delete_cookie('session')
            return {'success': True}
        else:
            return {'success': False, 'error': 'Failed to delete account'}
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

# Online users API
@app.ratelimit(10, 5)
@app.route('/api/users/online')
async def get_online_users() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    # Get list of currently connected users
    online_users = list(user_sockets.keys())
    current_user = app.get_username(session)

    # Remove current user from the list (don't show yourself in recipients)
    if current_user in online_users:
        online_users.remove(current_user)

    return {'success': True, 'users': sorted(online_users)}

# Private messaging (no storage, direct WebSocket only)
@app.ratelimit(5, 10)
@app.route('/api/messages', method='POST')
async def send_private_message() -> Any:
    session = app.get_cookie('session')
    if not session or not app.verify_session(session):
        return {'success': False, 'error': 'Not authenticated'}

    try:
        data = json.loads(app.request.body)
        recipient = data.get('recipient', '').strip()
        content = data.get('content', '').strip()

        if not recipient or not content:
            return {'success': False, 'error': 'Recipient and message content required'}

        if len(content) > 256:
            return {'success': False, 'error': 'Message too long (max 256 characters)'}

        sender = app.get_username(session)
        if sender == recipient:
            return {'success': False, 'error': 'Cannot send message to yourself'}

        # Check if recipient exists
        if not app.user_exists(recipient):
            return {'success': False, 'error': 'Recipient not found'}

        # Send private message directly via WebSocket to recipient (no storage)
        if recipient in user_sockets:
            try:
                await app.ws_send(user_sockets[recipient], f'[DM] {sender}: {content}')
            except Exception:
                # Socket might be closed, remove from mapping
                if recipient in user_sockets:
                    del user_sockets[recipient]

        return {'success': True}

    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid JSON'}
    except Exception:
        return {'success': False, 'error': 'Server error'}

# WebSocket chat
authenticated_users: dict[str, str] = {}  # socket_id -> username mapping
user_sockets: dict[str, app.socket.socket] = {}  # username -> socket mapping

@app.ratelimit(10, 50)
@app.route('/api/chat', method='ws')
async def websocket(sock: app.socket.socket):
    # sourcery skip: remove-unnecessary-cast
    # Get session token from the first message (should be the session token)
    session_token = await app.ws_recv(sock)

    if not session_token or not app.verify_session(session_token):
        await app.ws_send(sock, "Authentication required. Please log in.")
        return

    username = app.get_username(session_token)
    if not username:
        await app.ws_send(sock, "Invalid session. Please log in again.")
        return

    # Check if user is already connected
    socket_id = str(id(sock))
    if username in user_sockets:
        await app.ws_send(sock, "You are already connected from another session.")
        return

    authenticated_users[socket_id] = username
    user_sockets[username] = sock
    await app.ws_broadcast('/api/chat', f'{username} connected.')

    try:
        while True:
            data = await app.ws_recv(sock)
            if not data:
                break

            if len(data) > 256:
                await app.ws_send(sock, "Message too long")
                continue

            if app.ratelimit(sock, (6, 4), 'chat'):
                await app.ws_send(sock, "Stop spamming!")
                continue

            if app.ratelimit(sock, (0.2, -1), 'chat'):
                await app.ws_send(sock, "Stop spamming!")
                continue

            app.log(f'{username}: {data}')

            # Echo to all connected sockets
            await app.ws_broadcast('/api/chat', f'{username}: {data}')

    except Exception: ...
    finally:
        if socket_id in authenticated_users:
            username = authenticated_users[socket_id]
            del authenticated_users[socket_id]
            if username in user_sockets:
                del user_sockets[username]
            await app.ws_broadcast('/api/chat', f'{username} disconnected.')

### ERRORS ###
@app.error(404)
async def not_found() -> Any:
    return await app.template('static/404.html')

@app.error(500)
async def server_error() -> Any:
    return await app.template('static/500.html')


app.load_users('users.json')

app.serve('localhost')

app.save_users('users.json')
