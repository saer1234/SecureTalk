from __future__ import annotations

import base64
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request, send_file
from werkzeug.security import check_password_hash, generate_password_hash
import jwt

DB_PATH = os.environ.get('SECURETALK_DB', str(Path(__file__).with_name('securetalk.db')))
JWT_SECRET = os.environ.get('SECURETALK_JWT_SECRET', 'dev-change-me')
JWT_ISSUER = 'securetalk'
TOKEN_TTL_SECONDS = int(os.environ.get('SECURETALK_TOKEN_TTL', '86400'))

app = Flask(__name__)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('text','file')),
            filename TEXT,
            mimetype TEXT,
            wrapped_key_b64 TEXT NOT NULL,
            nonce_b64 TEXT NOT NULL,
            ciphertext_b64 TEXT NOT NULL,
            signature_b64 TEXT,
            sent_at INTEGER NOT NULL,
            FOREIGN KEY(sender) REFERENCES users(username),
            FOREIGN KEY(recipient) REFERENCES users(username)
        )
        """
    )
    conn.commit()
    conn.close()


def b64(s: bytes) -> str:
    return base64.b64encode(s).decode('utf-8')


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))


def make_token(username: str) -> str:
    now = int(time.time())
    payload = {
        'iss': JWT_ISSUER,
        'sub': username,
        'iat': now,
        'exp': now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def require_auth() -> str:
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        raise PermissionError('Missing Bearer token')
    token = auth.split(' ', 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], issuer=JWT_ISSUER)
    except Exception as e:
        raise PermissionError(f'Invalid token: {e}')
    return str(payload.get('sub'))


@app.get('/health')
def health() -> Any:
    return jsonify({'ok': True})


@app.post('/register')
def register() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    public_key_pem = data.get('public_key_pem') or ''

    if not username or not password or not public_key_pem:
        return jsonify({'error': 'username, password, public_key_pem required'}), 400

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, password_hash, public_key_pem, created_at) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), public_key_pem, int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'username already exists'}), 409
    finally:
        conn.close()

    return jsonify({'ok': True})


@app.post('/login')
def login() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    conn = db()
    cur = conn.cursor()
    row = cur.execute("SELECT username, password_hash FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not row or not check_password_hash(row['password_hash'], password):
        return jsonify({'error': 'invalid credentials'}), 401

    return jsonify({'token': make_token(username)})


@app.get('/public_key/<username>')
def get_public_key(username: str) -> Any:
    conn = db()
    cur = conn.cursor()
    row = cur.execute("SELECT public_key_pem FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'user not found'}), 404

    return jsonify({'username': username, 'public_key_pem': row['public_key_pem']})


@app.post('/send')
def send_message_or_file() -> Any:
    try:
        sender = require_auth()
    except PermissionError as e:
        return jsonify({'error': str(e)}), 401

    data = request.get_json(force=True, silent=True) or {}

    recipient = (data.get('recipient') or '').strip()
    kind = (data.get('kind') or '').strip()

    if kind not in ('text', 'file'):
        return jsonify({'error': "kind must be 'text' or 'file'"}), 400

    required_fields = ['wrapped_key_b64', 'nonce_b64', 'ciphertext_b64']
    if any(not data.get(f) for f in required_fields):
        return jsonify({'error': f"missing required fields: {', '.join(required_fields)}"}), 400

    if not recipient:
        return jsonify({'error': 'recipient required'}), 400

    filename = (data.get('filename') or '').strip() or None
    mimetype = (data.get('mimetype') or '').strip() or None
    signature_b64 = (data.get('signature_b64') or '').strip() or None

    # Ensure users exist (server still never decrypts).
    conn = db()
    cur = conn.cursor()
    if not cur.execute("SELECT 1 FROM users WHERE username=?", (recipient,)).fetchone():
        conn.close()
        return jsonify({'error': 'recipient not found'}), 404

    cur.execute(
        """
        INSERT INTO messages(sender, recipient, kind, filename, mimetype, wrapped_key_b64, nonce_b64, ciphertext_b64, signature_b64, sent_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            sender,
            recipient,
            kind,
            filename,
            mimetype,
            data['wrapped_key_b64'],
            data['nonce_b64'],
            data['ciphertext_b64'],
            signature_b64,
            int(time.time()),
        ),
    )
    msg_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'ok': True, 'id': msg_id})


@app.get('/inbox')
def inbox() -> Any:
    try:
        username = require_auth()
    except PermissionError as e:
        return jsonify({'error': str(e)}), 401

    conn = db()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT id, sender, recipient, kind, filename, mimetype, wrapped_key_b64, nonce_b64, ciphertext_b64, signature_b64, sent_at
        FROM messages
        WHERE recipient=?
        ORDER BY sent_at DESC
        """,
        (username,),
    ).fetchall()
    conn.close()

    messages = [dict(r) for r in rows]
    return jsonify({'messages': messages})


@app.get('/message/<int:msg_id>')
def get_message(msg_id: int) -> Any:
    try:
        username = require_auth()
    except PermissionError as e:
        return jsonify({'error': str(e)}), 401

    conn = db()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT id, sender, recipient, kind, filename, mimetype, wrapped_key_b64, nonce_b64, ciphertext_b64, signature_b64, sent_at
        FROM messages
        WHERE id=?
        """,
        (msg_id,),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'not found'}), 404
    if row['recipient'] != username:
        return jsonify({'error': 'forbidden'}), 403

    return jsonify(dict(row))


if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', '5000')), debug=True)
