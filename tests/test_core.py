from typing import Any, Dict
import httplib as app
import pathlib
import pytest


@pytest.mark.asyncio
async def test_url_encode_decode() -> None:
    s = 'Hello World!'
    encoded = await app.url_encode(s)
    assert '%20' in encoded
    decoded = await app.url_decode(encoded)
    assert decoded == s

@pytest.mark.asyncio
async def test_get_content_type() -> None:
    assert await app.get_content_type('index.html') == 'text/html'
    assert await app.get_content_type('style.css') == 'text/css'
    assert await app.get_content_type('data.json') == 'application/json'
    assert await app.get_content_type('image.png') == 'image/png'

def test_cookie_set_delete_headers():
    resp = app.Response()
    resp.set_cookie('x', 'y', path='/', max_age=3600, httponly=True, secure=True, samesite='Lax')
    headers = resp.get_cookie_headers()
    assert any('x=y' in h for h in headers)
    resp.delete_cookie('x')
    headers = resp.get_cookie_headers()
    assert any('x=' in h and 'Expires' in h or 'expires' in h for h in headers)

def test_user_create_login_session(tmp_path: pathlib.Path) -> None:
    # Clear state
    app.users.clear()
    app.profiles.clear()
    app.sessions.clear()

    assert app.create_user('alice', 'pass123') is True
    assert app.user_exists('alice') is True
    assert app.login('alice', 'pass123') is True
    assert app.login('alice', 'wrong') is False

    token = app.start_session('alice')
    assert app.verify_session(token) is True
    assert app.get_username(token) == 'alice'
    app.end_session(token)
    assert app.verify_session(token) is False

def test_save_load_users(tmp_path: pathlib.Path) -> None:
    # Prepare users
    app.users.clear()
    app.profiles.clear()
    app.create_user('bob', 'secret')
    app.update_user_profile('bob', 'hi')

    p = tmp_path / 'users.json'
    assert app.save_users(str(p)) is True
    # Clear and load
    app.users.clear()
    app.profiles.clear()
    assert app.load_users(str(p)) is True
    assert app.user_exists('bob')
    profile: Dict[str, Any] | None = app.get_user_profile('bob')
    assert profile is not None
    assert profile['bio'] == 'hi'

@pytest.mark.asyncio
async def test_template_and_redirect(tmp_path: pathlib.Path, monkeypatch: 'pytest.MonkeyPatch') -> None:
    # create a static file
    f = tmp_path / 'index.html'
    f.write_text('<h1>{{ title }}</h1>')
    # monkeypatch os.path to use tmp_path
    monkeypatch.setenv('PYHTTPLIB_TEST_STATIC', str(tmp_path))
    # patch _normalize_path to return our file name
    async def fake_normalize(path: str) -> str:
        return str(f)
    monkeypatch.setattr(app, '_normalize_path', fake_normalize)
    out = await app.template('index.html', title='Hi')
    assert '<h1>Hi</h1>' in out
    code, html = await app.redirect('https://example.com')
    assert code == 302
    assert 'refresh' in html.lower()
