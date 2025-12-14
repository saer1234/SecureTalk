from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from crypto_utils import (
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    rsa_decrypt_key,
    rsa_encrypt_key,
    rsa_sign,
    rsa_verify,
    stable_signing_payload,
    store_private_key,
    store_public_key,
)


DEFAULT_SERVER = os.environ.get('SECURETALK_SERVER', 'http://127.0.0.1:5000')
DATA_DIR = Path(os.environ.get('SECURETALK_HOME', str(Path.home() / '.securetalk')))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))


def user_dir(username: str) -> Path:
    return DATA_DIR / username


def token_path(username: str) -> Path:
    return user_dir(username) / 'token.json'


def save_token(username: str, token: str) -> None:
    ud = user_dir(username)
    ud.mkdir(parents=True, exist_ok=True)
    token_path(username).write_text(json.dumps({'token': token}))


def load_token(username: str) -> str:
    p = token_path(username)
    if not p.exists():
        raise SystemExit(f"No token found for '{username}'. Run: client.py login {username}")
    return json.loads(p.read_text())['token']


def headers_with_token(token: str) -> Dict[str, str]:
    return {'Authorization': f'Bearer {token}'}


def key_paths(username: str) -> Dict[str, Path]:
    ud = user_dir(username)
    return {
        'private': ud / 'private_key.pem',
        'public': ud / 'public_key.pem',
    }


def ensure_keys(username: str, passphrase: str) -> Dict[str, str]:
    kp = key_paths(username)
    if kp['private'].exists() and kp['public'].exists():
        return {
            'private_pem': kp['private'].read_text(),
            'public_pem': kp['public'].read_text(),
        }

    private, public = generate_rsa_keypair(key_size=3072)
    store_private_key(private, kp['private'], passphrase)
    store_public_key(public, kp['public'])
    return {
        'private_pem': kp['private'].read_text(),
        'public_pem': kp['public'].read_text(),
    }


def cmd_register(args: argparse.Namespace) -> None:
    username = args.username
    server = args.server

    password = getpass.getpass('Choose account password (server-side auth): ')
    key_pass = getpass.getpass('Choose key passphrase (encrypts your private key locally): ')
    ensure_keys(username, key_pass)

    public_pem = (user_dir(username) / 'public_key.pem').read_text()

    r = requests.post(f'{server}/register', json={
        'username': username,
        'password': password,
        'public_key_pem': public_pem,
    }, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f'Register failed: {r.status_code} {r.text}')

    print(r.json()['message'])


def cmd_login(args: argparse.Namespace) -> None:
    server = args.server
    username = args.username
    password = getpass.getpass('Password: ')

    r = requests.post(f'{server}/login', json={'username': username, 'password': password}, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f'Login failed: {r.status_code} {r.text}')

    token = r.json()['token']
    save_token(username, token)
    print('Logged in. Token saved locally.')


def cmd_send(args: argparse.Namespace) -> None:
    server = args.server
    sender = args.sender
    recipient = args.to
    token = load_token(sender)

    key_pass = getpass.getpass('Key passphrase (to use your private key for optional signing): ')

    # Load sender private (for signing) + fetch recipient public (for wrapping)
    sender_priv = load_private_key(key_paths(sender)['private'], key_pass)

    r_pub = requests.get(f'{server}/public_key/{recipient}', headers=headers_with_token(token), timeout=30)
    if r_pub.status_code != 200:
        raise SystemExit(f'Failed to get recipient public key: {r_pub.status_code} {r_pub.text}')
    recipient_pub = load_public_key(r_pub.json()['public_key_pem'].encode('utf-8'))

    # Content
    is_file = args.file is not None
    if is_file:
        file_path = Path(args.file)
        plaintext = file_path.read_bytes()
        filename = file_path.name
    else:
        plaintext = args.message.encode('utf-8')
        filename = None

    # Encrypt content with fresh AES key
    ct = encrypt_aes_gcm(plaintext)

    # Wrap AES key to recipient
    wrapped_key = rsa_encrypt_key(recipient_pub, ct.key)

    # Optional signature
    signature = None
    if args.sign:
        payload = stable_signing_payload(
            sender.encode('utf-8'),
            recipient.encode('utf-8'),
            b'file' if is_file else b'message',
            wrapped_key,
            ct.nonce,
            ct.ciphertext,
            ct.tag,
            (filename or '').encode('utf-8'),
        )
        signature = rsa_sign(sender_priv, payload)

    body: Dict[str, Any] = {
        'recipient': recipient,
        'kind': 'file' if is_file else 'message',
        'wrapped_key_b64': _b64(wrapped_key),
        'nonce_b64': _b64(ct.nonce),
        'ciphertext_b64': _b64(ct.ciphertext),
        'tag_b64': _b64(ct.tag),
        'filename': filename,
        'signature_b64': _b64(signature) if signature else None,
    }

    r = requests.post(f'{server}/send', json=body, headers=headers_with_token(token), timeout=60)
    if r.status_code != 200:
        raise SystemExit(f'Send failed: {r.status_code} {r.text}')

    print(f"Sent. Message id: {r.json()['id']}")


def cmd_inbox(args: argparse.Namespace) -> None:
    server = args.server
    username = args.username
    token = load_token(username)

    r = requests.get(f'{server}/inbox', headers=headers_with_token(token), timeout=30)
    if r.status_code != 200:
        raise SystemExit(f'Inbox failed: {r.status_code} {r.text}')

    items = r.json()['items']
    if not items:
        print('Inbox empty.')
        return

    for it in items:
        print(f"[{it['id']}] from={it['sender']} kind={it['kind']} filename={it.get('filename') or ''} at={it['created_at']}")


def cmd_read(args: argparse.Namespace) -> None:
    server = args.server
    username = args.username
    token = load_token(username)

    key_pass = getpass.getpass('Key passphrase: ')
    priv = load_private_key(key_paths(username)['private'], key_pass)

    r = requests.get(f'{server}/item/{args.id}', headers=headers_with_token(token), timeout=30)
    if r.status_code != 200:
        raise SystemExit(f'Read failed: {r.status_code} {r.text}')

    it = r.json()['item']

    # decrypt AES key
    aes_key = rsa_decrypt_key(priv, _unb64(it['wrapped_key_b64']))

    # decrypt content
    plaintext = decrypt_aes_gcm(
        key=aes_key,
        nonce=_unb64(it['nonce_b64']),
        ciphertext=_unb64(it['ciphertext_b64']),
        tag=_unb64(it['tag_b64']),
    )

    # verify signature if present
    if it.get('signature_b64'):
        r_spk = requests.get(f"{server}/public_key/{it['sender']}", headers=headers_with_token(token), timeout=30)
        if r_spk.status_code == 200:
            sender_pub = load_public_key(r_spk.json()['public_key_pem'].encode('utf-8'))
            payload = stable_signing_payload(
                it['sender'].encode('utf-8'),
                it['recipient'].encode('utf-8'),
                it['kind'].encode('utf-8'),
                _unb64(it['wrapped_key_b64']),
                _unb64(it['nonce_b64']),
                _unb64(it['ciphertext_b64']),
                _unb64(it['tag_b64']),
                (it.get('filename') or '').encode('utf-8'),
            )
            ok = rsa_verify(sender_pub, payload, _unb64(it['signature_b64']))
            print(f"Signature: {'VALID' if ok else 'INVALID'}")
        else:
            print('Signature: could not fetch sender public key to verify.')

    if it['kind'] == 'message':
        print('\n---MESSAGE---')
        print(plaintext.decode('utf-8', errors='replace'))
    else:
        out = Path(args.out or (Path.cwd() / (it.get('filename') or f"file_{args.id}.bin")))
        out.write_bytes(plaintext)
        print(f"File decrypted -> {out}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='SecureTalk Client (prototype)')
    p.add_argument('--server', default=DEFAULT_SERVER)

    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('register', help='Register a new user and upload public key')
    s.add_argument('username')
    s.set_defaults(func=cmd_register)

    s = sub.add_parser('login', help='Login to get token')
    s.add_argument('username')
    s.set_defaults(func=cmd_login)

    s = sub.add_parser('send', help='Send an encrypted message or file')
    s.add_argument('sender', help='your username')
    s.add_argument('--to', required=True, help='recipient username')
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument('--message', help='message text')
    g.add_argument('--file', help='file path to send')
    s.add_argument('--sign', action='store_true', help='attach digital signature (optional)')
    s.set_defaults(func=cmd_send)

    s = sub.add_parser('inbox', help='List inbox')
    s.add_argument('username')
    s.set_defaults(func=cmd_inbox)

    s = sub.add_parser('read', help='Decrypt and display/save an inbox item')
    s.add_argument('username')
    s.add_argument('id', type=int)
    s.add_argument('--out', help='output path for files')
    s.set_defaults(func=cmd_read)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
