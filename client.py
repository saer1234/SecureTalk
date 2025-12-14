import argparse
import base64
from pathlib import Path
from typing import Tuple

import requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ===== Crypto helpers =====

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """Generate an RSA 2048 key pair and return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None,
        backend=default_backend()
    )


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )


def rsa_encrypt(public_pem: bytes, data: bytes) -> str:
    """Encrypt small data (AES key) using RSA-OAEP and return base64 string."""
    public_key = load_public_key(public_pem)
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(private_pem: bytes, token: str) -> bytes:
    """Decrypt base64 RSA-OAEP ciphertext using the private key."""
    private_key = load_private_key(private_pem)
    ciphertext = base64.b64decode(token.encode("utf-8"))
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def aes_encrypt(plaintext: bytes):
    """
    Encrypt plaintext using AES-256-GCM.
    Returns (key, nonce, tag, ciphertext) as raw bytes.
    """
    import os
    key = os.urandom(32)  # AES-256 key
    nonce = os.urandom(12)  # recommended size for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return key, nonce, tag, ciphertext


def aes_decrypt(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def sign(private_pem: bytes, data: bytes) -> str:
    """
    Sign data with RSA-PSS and SHA256.
    Returns signature as base64 string.
    """
    private_key = load_private_key(private_pem)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_pem: bytes, data: bytes, signature_b64: str) -> bool:
    """Verify RSA-PSS signature. Returns True/False."""
    public_key = load_public_key(public_pem)
    signature = base64.b64decode(signature_b64.encode("utf-8"))
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ===== Client helpers =====

KEYS_DIR = Path("keys")


def get_key_paths(username: str):
    KEYS_DIR.mkdir(exist_ok=True)
    priv_path = KEYS_DIR / f"{username}_private.pem"
    pub_path = KEYS_DIR / f"{username}_public.pem"
    return priv_path, pub_path


def save_keys(username: str, private_pem: bytes, public_pem: bytes):
    priv_path, pub_path = get_key_paths(username)
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    print(f"Saved private key to {priv_path}")
    print(f"Saved public key to {pub_path}")


def load_keys(username: str) -> Tuple[bytes, bytes]:
    priv_path, pub_path = get_key_paths(username)
    if not priv_path.exists() or not pub_path.exists():
        raise RuntimeError(f"Keys for user '{username}' do not exist. Run 'register' first.")
    return priv_path.read_bytes(), pub_path.read_bytes()


def fetch_public_key(base_url: str, username: str) -> bytes:
    resp = requests.get(f"{base_url}/users/{username}/public_key", timeout=5)
    if resp.status_code != 200:
        raise RuntimeError(f"Could not fetch public key for '{username}': {resp.text}")
    data = resp.json()
    return data["public_key"].encode("utf-8")


# ===== Commands =====

def cmd_register(args):
    base_url = args.server.rstrip("/")
    username = args.username
    private_pem, public_pem = generate_rsa_keypair()

    # send public key to server
    resp = requests.post(
        f"{base_url}/register",
        json={"username": username, "public_key": public_pem.decode("utf-8")},
        timeout=5
    )
    if resp.status_code != 200:
        print("Error from server:", resp.text)
        return

    save_keys(username, private_pem, public_pem)
    print("Registered successfully on server.")


def cmd_send_message(args):
    base_url = args.server.rstrip("/")
    sender = args.sender
    recipient = args.recipient
    text = args.text

    private_pem, _ = load_keys(sender)
    recipient_pub = fetch_public_key(base_url, recipient)

    plaintext_bytes = text.encode("utf-8")
    key, nonce, tag, ciphertext = aes_encrypt(plaintext_bytes)

    encrypted_key = rsa_encrypt(recipient_pub, key)

    payload = {
        "from": sender,
        "to": recipient,
        "encrypted_key": encrypted_key,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "is_file": False,
        "filename": None,
    }

    # Optional digital signature (sign ciphertext)
    if args.sign:
        signature = sign(private_pem, ciphertext)
        payload["signature"] = signature

    resp = requests.post(f"{base_url}/send", json=payload, timeout=10)
    if resp.status_code != 200:
        print("Error from server:", resp.text)
    else:
        print("Message sent successfully. ID:", resp.json().get("id"))


def cmd_send_file(args):
    base_url = args.server.rstrip("/")
    sender = args.sender
    recipient = args.recipient
    file_path = Path(args.file)

    if not file_path.exists():
        print(f"File not found: {file_path}")
        return

    private_pem, _ = load_keys(sender)
    recipient_pub = fetch_public_key(base_url, recipient)

    file_bytes = file_path.read_bytes()
    key, nonce, tag, ciphertext = aes_encrypt(file_bytes)
    encrypted_key = rsa_encrypt(recipient_pub, key)

    payload = {
        "from": sender,
        "to": recipient,
        "encrypted_key": encrypted_key,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "is_file": True,
        "filename": file_path.name,
    }

    if args.sign:
        signature = sign(private_pem, ciphertext)
        payload["signature"] = signature

    resp = requests.post(f"{base_url}/send", json=payload, timeout=20)
    if resp.status_code != 200:
        print("Error from server:", resp.text)
    else:
        print("File sent successfully. ID:", resp.json().get("id"))


def cmd_inbox(args):
    base_url = args.server.rstrip("/")
    username = args.username
    private_pem, _ = load_keys(username)

    resp = requests.get(f"{base_url}/inbox/{username}", timeout=10)
    if resp.status_code != 200:
        print("Error from server:", resp.text)
        return

    data = resp.json()
    messages = data.get("messages", [])
    if not messages:
        print("Inbox is empty.")
        return

    print(f"Inbox for {username}:")
    for msg in messages:
        print("=" * 40)
        print(f"ID: {msg['id']}")
        print(f"From: {msg['from']}")
        print(f"To: {msg['to']}")
        print(f"Created at: {msg.get('created_at')}")
        is_file = msg.get("is_file", False)
        filename = msg.get("filename")

        # 1) Decrypt AES key with recipient's private key
        key_bytes = rsa_decrypt(private_pem, msg["encrypted_key"])

        # 2) Decrypt content with AES
        nonce = base64.b64decode(msg["nonce"].encode("utf-8"))
        tag = base64.b64decode(msg["tag"].encode("utf-8"))
        ciphertext = base64.b64decode(msg["ciphertext"].encode("utf-8"))

        try:
            plaintext = aes_decrypt(key_bytes, nonce, tag, ciphertext)
        except Exception as e:
            print("!! Failed to decrypt message:", e)
            continue

        # 3) Verify optional signature using sender's public key
        signature = msg.get("signature")
        if signature:
            try:
                sender_pub = fetch_public_key(base_url, msg["from"])
                ok = verify_signature(sender_pub, ciphertext, signature)
            except Exception as e:
                ok = False
                print("!! Failed to verify signature:", e)
            print(f"Signature valid: {ok}")

        # 4) Show or save decrypted content
        if is_file:
            out_dir = Path(args.output or ".")
            out_dir.mkdir(exist_ok=True)
            out_path = out_dir / (filename or f"{msg['id']}.bin")
            out_path.write_bytes(plaintext)
            print(f"[FILE] Saved decrypted file to: {out_path}")
        else:
            print("Message text:")
            print(plaintext.decode("utf-8", errors="replace"))


def cmd_list_users(args):
    base_url = args.server.rstrip("/")
    resp = requests.get(f"{base_url}/users", timeout=5)
    if resp.status_code != 200:
        print("Error from server:", resp.text)
        return
    users = resp.json().get("users", [])
    print("Users on server:")
    for u in users:
        print("-", u)


def main():
    parser = argparse.ArgumentParser(description="SecureTalk client")
    parser.add_argument(
        "--server",
        default="http://127.0.0.1:5000",
        help="Base URL of SecureTalk server (default: %(default)s)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # register
    p_reg = subparsers.add_parser("register", help="Register a new user")
    p_reg.add_argument("username")
    p_reg.set_defaults(func=cmd_register)

    # send-message
    p_send = subparsers.add_parser("send-message", help="Send encrypted message")
    p_send.add_argument("sender")
    p_send.add_argument("recipient")
    p_send.add_argument("text", help="Message text")
    p_send.add_argument("--sign", action="store_true", help="Digitally sign the message")
    p_send.set_defaults(func=cmd_send_message)

    # send-file
    p_file = subparsers.add_parser("send-file", help="Send encrypted file")
    p_file.add_argument("sender")
    p_file.add_argument("recipient")
    p_file.add_argument("file")
    p_file.add_argument("--sign", action="store_true", help="Digitally sign the file")
    p_file.set_defaults(func=cmd_send_file)

    # inbox
    p_inbox = subparsers.add_parser("inbox", help="Read and decrypt inbox")
    p_inbox.add_argument("username")
    p_inbox.add_argument("--output", help="Directory to save decrypted files")
    p_inbox.set_defaults(func=cmd_inbox)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List users on server")
    p_list.set_defaults(func=cmd_list_users)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
