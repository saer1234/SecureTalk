# SecureTalk (Hybrid Cryptography System)

This is a working prototype of the **SecureTalk** hybrid cryptography system described in your document.

## What it does
- Client generates/stores a **public/private key pair** locally.
- Message/file content is encrypted with a fresh **AES-256-GCM** session key.
- Session key is encrypted with the recipient's **public key (RSA-OAEP)**.
- Server stores/forwards **only encrypted data** (never decrypts).
- Optional **digital signatures (RSA-PSS)** for sender authenticity + integrity.

## Quick start

### 1) Install
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### 2) Run server
```bash
export FLASK_ENV=development
python server.py
```
By default it listens on `http://127.0.0.1:5000` and creates `securetalk.db` next to `server.py`.

### 3) Register users (client)
Open two terminals:

**Terminal A (Alice):**
```bash
python client.py register --server http://127.0.0.1:5000 --user alice
```

**Terminal B (Bob):**
```bash
python client.py register --server http://127.0.0.1:5000 --user bob
```

Keys are stored under:
- Linux/Mac: `~/.securetalk/<username>/`
- Windows: `%USERPROFILE%\\.securetalk\\<username>\\`

### 4) Send an encrypted message
From Alice:
```bash
python client.py send-msg --server http://127.0.0.1:5000 --from alice --to bob --sign \
  --text "Hello Bob, this is end-to-end encrypted."
```

### 5) Read inbox + decrypt
From Bob:
```bash
python client.py inbox --server http://127.0.0.1:5000 --user bob
python client.py read --server http://127.0.0.1:5000 --user bob --id 1
```

### 6) Send an encrypted file
From Alice:
```bash
python client.py send-file --server http://127.0.0.1:5000 --from alice --to bob --sign --path ./some.pdf
```

On Bob:
```bash
python client.py inbox --server http://127.0.0.1:5000 --user bob
python client.py read --server http://127.0.0.1:5000 --user bob --id 2 --out ./decrypted.pdf
```

## API (server)
- `POST /register` {username, password, public_key_pem}
- `POST /login` {username, password} -> {token}
- `GET /public_key/<username>`
- `POST /send` (auth) encrypted payload (message or file)
- `GET /inbox/<username>` (auth)
- `GET /item/<id>` (auth) full encrypted payload

## Notes / Limitations
- Prototype security (JWT secret, local key storage) is for a demo.
- No forward secrecy (like Signal/Double Ratchet); each item uses a fresh AES key but long-term RSA keys.
- For a production version you’d add rate limiting, HTTPS, device key rotation, audit logging, etc.
