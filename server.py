import os, json, socket, threading, base64, hashlib, hmac
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


HOST = "0.0.0.0"
PORT = 5000

DATA_DIR = "data"
USERS_JSON = os.path.join(DATA_DIR, "users.json")
MSGS_JSON = os.path.join(DATA_DIR, "messages.json")
PLUGINS_JSON = os.path.join(DATA_DIR, "plugins.json")
PLUGINS_DIR = os.path.join(DATA_DIR, "plugins")

users_lock = threading.Lock()
msgs_lock = threading.Lock()
plugins_lock = threading.Lock()

MAX_LINE_BYTES = 50_000_000

C_RST = "\033[0m"
C_G = "\033[32m"
C_B = "\033[34m"
C_Y = "\033[33m"
C_R = "\033[31m"
C_C = "\033[36m"
C_M = "\033[35m"


def t():
    return datetime.now().strftime("%H:%M:%S")


def log_plus(msg):
    print(f"{C_G}[+]{C_RST} {msg}", flush=True)


def log_star(msg):
    print(f"{C_B}[*]{C_RST} {msg}", flush=True)


def log_warn(msg):
    print(f"{C_Y}[!]{C_RST} {msg}", flush=True)


def log_err(msg):
    print(f"{C_R}[-]{C_RST} {msg}", flush=True)


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(PLUGINS_DIR, exist_ok=True)

    if not os.path.exists(USERS_JSON):
        with open(USERS_JSON, "w", encoding="utf-8") as f:
            json.dump({}, f)

    if not os.path.exists(MSGS_JSON):
        with open(MSGS_JSON, "w", encoding="utf-8") as f:
            json.dump({}, f)

    if not os.path.exists(PLUGINS_JSON):
        with open(PLUGINS_JSON, "w", encoding="utf-8") as f:
            json.dump({"next_id": 1, "items": []}, f)


def now_ts():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def pbkdf_hash(p, s, it=200_000):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), s, it, dklen=32)


def secure_compare(a, b):
    return hmac.compare_digest(a, b)


def read_json(path, lock):
    with lock:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def write_json(path, data, lock):
    tmp = path + ".tmp"
    with lock:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)


def send_json(conn, obj):
    conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode())


def recv_json_line(conn, maxlen=MAX_LINE_BYTES):
    buf = bytearray()

    while True:
        ch = conn.recv(1)
        if not ch:
            if not buf:
                return None
            break

        buf += ch

        if len(buf) > maxlen:
            raise ValueError("too long")

        if ch == b"\n":
            break

    line = buf.decode("utf-8", "replace").rstrip("\r\n")

    if not line:
        return None

    return json.loads(line)


def key_fingerprint_hex(pub_pem):
    try:
        k = RSA.import_key(pub_pem.encode())
        der = k.export_key("DER")
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return None


def handle_register(req):
    u = (req.get("username", "") or "").strip().lower()
    p = req.get("password", "")
    pub = req.get("public_pem", "")

    if not u or not p or not pub:
        return {"ok": False, "msg": "username/password/public_pem required"}

    users = read_json(USERS_JSON, users_lock)

    if u in users:
        return {"ok": False, "msg": "username exists"}

    salt = os.urandom(16)
    ph = pbkdf_hash(p, salt)

    users[u] = {
        "password_hash_b64": base64.b64encode(ph).decode(),
        "salt_hex": salt.hex(),
        "public_pem": pub,
        "created_at": now_ts(),
    }

    write_json(USERS_JSON, users, users_lock)

    msgs = read_json(MSGS_JSON, msgs_lock)

    if u not in msgs:
        msgs[u] = []
        write_json(MSGS_JSON, msgs, msgs_lock)

    log_plus(f"{t()} register {C_C}{u}{C_RST}")

    return {"ok": True, "msg": f"registered {u}"}


def handle_login(req, session):
    u = (req.get("username", "") or "").strip().lower()
    p = req.get("password", "")

    if not u or not p:
        return {"ok": False, "msg": "username/password required"}

    users = read_json(USERS_JSON, users_lock)
    rec = users.get(u)

    if not rec:
        return {"ok": False, "msg": "invalid credentials"}

    salt = bytes.fromhex(rec["salt_hex"])
    exp = base64.b64decode(rec["password_hash_b64"])
    got = pbkdf_hash(p, salt)

    if not secure_compare(got, exp):
        return {"ok": False, "msg": "invalid credentials"}

    session["user"] = u
    session.pop("challenge", None)
    session.pop("plugin_challenge", None)

    log_star(f"{t()} login {C_C}{u}{C_RST}")

    return {"ok": True, "msg": f"logged in as {u}"}


def handle_logout(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "not logged in"}

    session["user"] = None
    session.pop("challenge", None)
    session.pop("plugin_challenge", None)

    log_star(f"{t()} logout {C_C}{u}{C_RST}")

    return {"ok": True, "msg": "logged out"}


def handle_get_pubkey(req):
    u = (req.get("username", "") or "").strip().lower()

    if not u:
        return {"ok": False, "msg": "username required"}

    users = read_json(USERS_JSON, users_lock)
    rec = users.get(u)

    if not rec:
        return {"ok": False, "msg": "not found"}

    return {"ok": True, "public_pem": rec["public_pem"]}


def handle_send(req, session):
    user = session.get("user")

    if not user:
        return {"ok": False, "msg": "login required"}

    r = (req.get("recipient", "") or "").strip().lower()
    payload = req.get("payload")

    if not r or not isinstance(payload, dict):
        return {"ok": False, "msg": "recipient/payload required"}

    msgs = read_json(MSGS_JSON, msgs_lock)

    if r not in msgs:
        msgs[r] = []

    nid = (max((m["id"] for m in msgs[r]), default=0) + 1) if msgs[r] else 1

    rec = {
        "id": nid,
        "sender": user,
        "ts": now_ts(),
        "payload": payload,
    }

    msgs[r].append(rec)
    write_json(MSGS_JSON, msgs, msgs_lock)

    log_plus(f"{t()} store msg #{nid} {C_C}{user}{C_RST}->{C_M}{r}{C_RST}")

    return {"ok": True, "message_id": nid}


def handle_list(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    msgs = read_json(MSGS_JSON, msgs_lock)
    inbox = msgs.get(u, [])

    out = [
        {"idx": i + 1, "id": m["id"], "from": m["sender"], "ts": m["ts"]}
        for i, m in enumerate(inbox)
    ]

    log_star(f"{t()} list inbox {C_C}{u}{C_RST} ({len(out)} items)")

    return {"ok": True, "inbox": out}


def handle_get(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    idx = req.get("index")

    msgs = read_json(MSGS_JSON, msgs_lock)
    inbox = msgs.get(u, [])

    if not isinstance(idx, int) or idx < 1 or idx > len(inbox):
        return {"ok": False, "msg": "invalid index"}

    m = inbox[idx - 1]

    log_star(f"{t()} get msg idx {idx} for {C_C}{u}{C_RST}")

    return {"ok": True, "payload": m["payload"], "meta": {"id": m["id"], "from": m["sender"], "ts": m["ts"]}}


def handle_upload_plugin(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    name = (req.get("plugin_name", "") or "").strip()
    pdf_b64 = req.get("pdf_b64", "")
    sig_b64 = req.get("sig_b64", "")

    if not name or not isinstance(pdf_b64, str) or not isinstance(sig_b64, str):
        return {"ok": False, "msg": "plugin_name/pdf_b64/sig_b64 required"}

    users = read_json(USERS_JSON, users_lock)
    rec = users.get(u)

    if not rec:
        return {"ok": False, "msg": "user not found"}

    pub = RSA.import_key(rec["public_pem"].encode())

    file_bytes = base64.b64decode(pdf_b64)
    h = SHA256.new(file_bytes)

    try:
        pss.new(pub).verify(h, base64.b64decode(sig_b64))
    except (ValueError, TypeError):
        log_err(f"{t()} plugin upload signature invalid by {C_C}{u}{C_RST}")
        return {"ok": False, "msg": "signature invalid"}

    data = read_json(PLUGINS_JSON, plugins_lock)

    pid = data["next_id"]
    data["next_id"] = pid + 1

    filename = f"plugin_{pid}.pdf"

    with open(os.path.join(PLUGINS_DIR, filename), "wb") as f:
        f.write(file_bytes)

    item = {
        "id": pid,
        "name": name,
        "author": u,
        "filename": filename,
        "uploaded_at": now_ts(),
        "sig_b64": sig_b64,
        "sha256": h.hexdigest(),
    }

    data["items"].append(item)
    write_json(PLUGINS_JSON, data, plugins_lock)

    log_plus(f"{t()} plugin upload id={pid} by {C_C}{u}{C_RST} name='{name}'")

    return {"ok": True, "plugin_id": pid}


def handle_list_plugins(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    data = read_json(PLUGINS_JSON, plugins_lock)
    users = read_json(USERS_JSON, users_lock)

    items = []

    for it in data["items"]:
        dev = it["author"]
        pub = users.get(dev, {}).get("public_pem", "")
        fpr = key_fingerprint_hex(pub) or ""
        items.append(
            {
                "id": it["id"],
                "name": it["name"],
                "author": dev,
                "uploaded_at": it["uploaded_at"],
                "key_fpr": f"{fpr[:16]}..." if fpr else "",
            }
        )

    log_star(f"{t()} list plugins to {C_C}{u}{C_RST} ({len(items)} items)")

    return {"ok": True, "plugins": items}


def handle_plugin_challenge(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    pid = req.get("plugin_id")

    if not isinstance(pid, int):
        return {"ok": False, "msg": "plugin_id required"}

    data = read_json(PLUGINS_JSON, plugins_lock)
    ok = any(it["id"] == pid for it in data["items"])

    if not ok:
        return {"ok": False, "msg": "plugin not found"}

    nonce = os.urandom(32)
    cid = int.from_bytes(os.urandom(4), "big")

    session["plugin_challenge"] = {
        "id": cid,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "plugin_id": pid,
    }

    log_star(f"{t()} plugin challenge to {C_C}{u}{C_RST} pid={pid} id={cid}")

    return {"ok": True, "challenge_id": cid, "nonce_b64": session["plugin_challenge"]["nonce_b64"]}


def handle_plugin_download(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    ch = session.get("plugin_challenge")

    if not ch:
        return {"ok": False, "msg": "no active plugin challenge"}

    cid = req.get("challenge_id")
    sig_b64 = req.get("signature_b64")

    if cid != ch["id"] or not isinstance(sig_b64, str):
        return {"ok": False, "msg": "invalid proof"}

    users = read_json(USERS_JSON, users_lock)
    rec = users.get(u)

    if not rec:
        return {"ok": False, "msg": "user not found"}

    pub_user = RSA.import_key(rec["public_pem"].encode())

    h = SHA256.new(base64.b64decode(ch["nonce_b64"]))

    try:
        pss.new(pub_user).verify(h, base64.b64decode(sig_b64))
    except (ValueError, TypeError):
        log_err(f"{t()} plugin auth fail {C_C}{u}{C_RST} id={cid}")
        return {"ok": False, "msg": "signature verification failed"}

    pid = ch["plugin_id"]

    data = read_json(PLUGINS_JSON, plugins_lock)
    it = next((x for x in data["items"] if x["id"] == pid), None)

    if not it:
        return {"ok": False, "msg": "plugin not found"}

    path = os.path.join(PLUGINS_DIR, it["filename"])

    try:
        with open(path, "rb") as f:
            file_b64 = base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        return {"ok": False, "msg": "file missing"}

    users_all = read_json(USERS_JSON, users_lock)
    dev_pub = users_all.get(it["author"], {}).get("public_pem", "")
    fpr = key_fingerprint_hex(dev_pub) or ""

    session.pop("plugin_challenge", None)

    log_plus(f"{t()} plugin download ok {C_C}{u}{C_RST} pid={pid}")

    return {
        "ok": True,
        "plugin": {
            "id": it["id"],
            "name": it["name"],
            "author": it["author"],
            "uploaded_at": it["uploaded_at"],
            "key_fpr": f"{fpr[:16]}..." if fpr else "",
        },
        "file_b64": file_b64,
        "dev_signature_b64": it["sig_b64"],
        "dev_public_pem": dev_pub,
        "sha256": it["sha256"],
    }


def handle_challenge(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    nonce = os.urandom(32)
    cid = int.from_bytes(os.urandom(4), "big")

    session["challenge"] = {
        "id": cid,
        "nonce_b64": base64.b64encode(nonce).decode(),
    }

    log_star(f"{t()} challenge issued to {C_C}{u}{C_RST} id={cid}")

    return {"ok": True, "challenge_id": cid, "nonce_b64": session["challenge"]["nonce_b64"]}


def handle_prove(req, session):
    u = session.get("user")

    if not u:
        return {"ok": False, "msg": "login required"}

    ch = session.get("challenge")

    if not ch:
        return {"ok": False, "msg": "no active challenge"}

    cid = req.get("challenge_id")
    sig_b64 = req.get("signature_b64")

    if cid != ch["id"] or not isinstance(sig_b64, str):
        return {"ok": False, "msg": "invalid proof"}

    users = read_json(USERS_JSON, users_lock)
    rec = users.get(u)

    if not rec:
        return {"ok": False, "msg": "user not found"}

    pub = RSA.import_key(rec["public_pem"].encode())
    h = SHA256.new(base64.b64decode(ch["nonce_b64"]))

    try:
        pss.new(pub).verify(h, base64.b64decode(sig_b64))
    except (ValueError, TypeError):
        log_err(f"{t()} auth fail {C_C}{u}{C_RST} id={cid}")
        return {"ok": False, "msg": "signature verification failed"}

    session.pop("challenge", None)

    log_plus(f"{t()} auth ok {C_C}{u}{C_RST} id={cid}")

    return {"ok": True, "msg": "authentication success"}


def client_thread(conn, addr):
    log_plus(f"{t()} connect {addr[0]}:{addr[1]}")
    session = {"user": None}

    try:
        send_json(conn, {"ok": True, "msg": "Mini Mail Server ready"})

        while True:
            try:
                req = recv_json_line(conn)
            except ValueError as e:
                log_err(f"{t()} recv error: {e}")
                break

            if req is None:
                break

            if not isinstance(req, dict):
                send_json(conn, {"ok": False, "msg": "invalid request"})
                continue

            act = req.get("action", "")

            try:
                if act == "register":
                    resp = handle_register(req)

                elif act == "login":
                    resp = handle_login(req, session)

                elif act == "logout":
                    resp = handle_logout(req, session)

                elif act == "get_pubkey":
                    resp = handle_get_pubkey(req)

                elif act == "send":
                    resp = handle_send(req, session)

                elif act == "list":
                    resp = handle_list(req, session)

                elif act == "get":
                    resp = handle_get(req, session)

                elif act == "upload_plugin":
                    resp = handle_upload_plugin(req, session)

                elif act == "list_plugins":
                    resp = handle_list_plugins(req, session)

                elif act == "plugin_challenge":
                    resp = handle_plugin_challenge(req, session)

                elif act == "plugin_download":
                    resp = handle_plugin_download(req, session)

                elif act == "challenge":
                    resp = handle_challenge(req, session)

                elif act == "prove":
                    resp = handle_prove(req, session)

                elif act == "quit":
                    send_json(conn, {"ok": True, "msg": "bye"})
                    break

                else:
                    resp = {"ok": False, "msg": "unknown action"}

            except Exception as e:
                log_err(f"{t()} error {str(e)}")
                resp = {"ok": False, "msg": f"error: {e}"}

            send_json(conn, resp)

    except (ConnectionResetError, BrokenPipeError):
        log_warn(f"{t()} peer closed {addr[0]}:{addr[1]}")

    finally:
        conn.close()
        log_star(f"{t()} disconnect {addr[0]}:{addr[1]}")


def main():
    ensure_dirs()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(16)

        log_plus(f"{t()} listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
