from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os
from uuid import uuid4
from datetime import datetime
from threading import Lock

DATA_FILE = "server_data.json"

app = Flask(__name__)
CORS(app)
_data_lock = Lock()


def load_data():
    """Load server data from JSON file."""
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "messages": []}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {"users": {}, "messages": []}


def save_data(data):
    """Save server data to JSON file."""
    with _data_lock:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f,indent=2)


@app.route("/")
def index():
    """Serve the main web frontend."""
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user and store their public key.
    Body JSON:
    {
        "username": "alice",
        "public_key": "-----BEGIN PUBLIC KEY...."
    }
    """
    payload = request.get_json(force=True) or {}
    username = payload.get("username")
    public_key = payload.get("public_key")

    if not username or not public_key:
        return jsonify({"error": "username and public_key are required"}), 400

    data = load_data()

    if username in data["users"]:
        return jsonify({"error": "username already exists"}), 400

    data["users"][username] = {"public_key": public_key}
    save_data(data)
    return jsonify({"status": "ok", "username": username})


@app.route("/users", methods=["GET"])
def list_users():
    """List all registered users."""
    data = load_data()
    return jsonify({"users": list(data["users"].keys())})


@app.route("/users/<username>/public_key", methods=["GET"])
def get_public_key(username):
    """Return the stored public key of a given username."""
    data = load_data()
    user = data["users"].get(username)
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": username, "public_key": user["public_key"]})


@app.route("/send", methods=["POST"])
def send():
    """
    Store an encrypted message or file.

    Body JSON:
    {
        "from": "alice",
        "to": "bob",
        "encrypted_key": "...",   # RSA-encrypted AES key (base64)
        "nonce": "...",           # AES nonce (base64)
        "tag": "...",             # AES GCM tag (base64)
        "ciphertext": "...",      # encrypted content (base64)
        "is_file": true/false,
        "filename": "example.txt" or null,
        "signature": "..." (optional)
    }
    """
    payload = request.get_json(force=True) or {}

    required_fields = ["from", "to", "encrypted_key", "nonce", "tag", "ciphertext"]
    missing = [f for f in required_fields if f not in payload or payload[f] is None]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    data = load_data()

    if payload["from"] not in data["users"] or payload["to"] not in data["users"]:
        return jsonify({"error": "sender or recipient does not exist"}), 400

    message = {
        "id": str(uuid4()),
        "from": payload["from"],
        "to": payload["to"],
        "encrypted_key": payload["encrypted_key"],
        "nonce": payload["nonce"],
        "tag": payload["tag"],
        "ciphertext": payload["ciphertext"],
        "is_file": bool(payload.get("is_file", False)),
        "filename": payload.get("filename"),
        "signature": payload.get("signature"),
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    data["messages"].append(message)
    save_data(data)
    return jsonify({"status": "ok", "id": message["id"]})


@app.route("/inbox/<username>", methods=["GET"])
def inbox(username):
    """
    Return all messages for a given user.
    NOTE: They remain encrypted; client will decrypt them.
    """
    data = load_data()
    if username not in data["users"]:
        return jsonify({"error": "user not found"}), 404

    msgs = [m for m in data["messages"] if m["to"] == username]
    return jsonify({"messages": msgs})


if __name__ == "__main__":
    # For development/evaluation
    app.run(host="0.0.0.0", port=5000, debug=True)
