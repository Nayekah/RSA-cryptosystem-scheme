import os, json, socket, sys, base64, hashlib
from getpass import getpass
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

KEYS_DIR = "keys"
DOWNLOADS_DIR = "downloads"

MAX_LINE_BYTES = 50_000_000

ART = r"""░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░       ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓████████▓▒░ 
       ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
     ░▒▓██▓▒░       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░         ░▒▓█▓▒░     
   ░▒▓██▓▒░  ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒▒▓███▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░    ░▒▓█▓▒░     
 ░▒▓██▓▒░           ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░       ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░  ░▒▓█▓▒░     
"""

C_RST = "\033[0m"
C_G = "\033[32m"
C_B = "\033[34m"
C_Y = "\033[33m"
C_R = "\033[31m"
C_C = "\033[36m"
C_M = "\033[35m"
C_W = "\033[37m"


def p_label(txt):
    print(f"{C_C}{txt}{C_RST}", flush=True)


def p_ok(txt):
    print(f"{C_G}[+]{C_RST} {txt}", flush=True)


def p_info(txt):
    print(f"{C_B}[*]{C_RST} {txt}", flush=True)


def p_warn(txt):
    print(f"{C_Y}[!]{C_RST} {txt}", flush=True)


def p_err(txt):
    print(f"{C_R}[-]{C_RST} {txt}", flush=True)


def prompt():
    return input(f"\n{C_M}>> {C_RST}")


def cls():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def show_art():
    cls()
    print(f"{C_M}{ART}{C_RST}", flush=True)


def pause():
    p_label("Press Enter to continue")
    prompt()


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def ensure_key_dir(u):
    p = os.path.join(KEYS_DIR, u)
    ensure_dir(p)
    return p


def my_priv_path(user):
    return os.path.join(KEYS_DIR, user, "private.pem")


def send_json(sock, obj):
    sock.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode())


def recv_json_line(sock, maxlen=MAX_LINE_BYTES):
    buf = bytearray()

    while True:
        ch = sock.recv(1)
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


def rsa_encrypt_chunks(data_bytes, public_pem_bytes):
    key = RSA.import_key(public_pem_bytes)
    k = key.size_in_bytes()
    hlen = 32
    max_pt = k - 2 * hlen - 2
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    out = []

    for i in range(0, len(data_bytes), max_pt):
        ct = cipher.encrypt(data_bytes[i:i + max_pt])
        out.append(b64encode(ct).decode())

    return {"scheme": "RSA-OAEP-SHA256", "chunks": out, "k": k}


def rsa_decrypt_chunks(payload, private_pem_path):
    with open(private_pem_path, "rb") as f:
        key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)

    parts = payload.get("chunks", [])
    acc = bytearray()

    for b64 in parts:
        ct = b64decode(b64)
        acc += cipher.decrypt(ct)

    return bytes(acc)


def encrypt_message_rsa(plaintext, recipient_public_pem_bytes):
    return rsa_encrypt_chunks(plaintext.encode(), recipient_public_pem_bytes)


def decrypt_message_rsa(payload, private_path):
    return rsa_decrypt_chunks(payload, private_path).decode("utf-8", "replace")


def sign_bytes_rsa(data_bytes, private_pem_path):
    with open(private_pem_path, "rb") as f:
        key = RSA.import_key(f.read())

    h = SHA256.new(data_bytes)
    sig = pss.new(key).sign(h)

    return b64encode(sig).decode()


def verify_bytes_sig_rsa(data_bytes, sig_b64, public_pem):
    pub = RSA.import_key(public_pem.encode())
    h = SHA256.new(data_bytes)

    try:
        pss.new(pub).verify(h, b64decode(sig_b64))
        return True
    except (ValueError, TypeError):
        return False


def key_fingerprint_hex(pub_pem):
    try:
        k = RSA.import_key(pub_pem.encode())
        der = k.export_key("DER")
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


def do_register(sock):
    show_art()

    p_label("Enter username (case-insensitive):")
    u = prompt().strip().lower()

    p_label("Enter password (hidden):")
    p = getpass(f"\n{C_M}>> {C_RST}")

    key = RSA.generate(2048)
    pub = key.public_key().export_key("PEM").decode()
    priv = key.export_key("PEM").decode()

    send_json(
        sock,
        {"action": "register", "username": u, "password": p, "public_pem": pub},
    )

    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Registration failed: {None if not resp else resp.get('msg')}")
        pause()
        return None

    up = ensure_key_dir(u)

    with open(os.path.join(up, "public.pem"), "w", encoding="utf-8") as f:
        f.write(pub)

    with open(os.path.join(up, "private.pem"), "w", encoding="utf-8") as f:
        f.write(priv)

    try:
        if os.name == "posix":
            os.chmod(os.path.join(up, "private.pem"), 0o600)
    except Exception:
        pass

    p_ok(f"Registered. Keys saved in: {up}")

    pause()
    return u


def do_login(sock, state):
    show_art()

    p_label("Enter username (case-insensitive):")
    u = prompt().strip().lower()

    p_label("Enter password (hidden):")
    p = getpass(f"\n{C_M}>> {C_RST}")

    send_json(sock, {"action": "login", "username": u, "password": p})

    resp = recv_json_line(sock)

    if resp and resp.get("ok"):
        state["user"] = u
        p_ok("Login successful")
    else:
        p_err(f"Login failed: {None if not resp else resp.get('msg')}")

    pause()


def fetch_pubkey(sock, username):
    send_json(sock, {"action": "get_pubkey", "username": username})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        return None

    return resp["public_pem"].encode()


def do_send(sock, state):
    if not state.get("user"):
        p_warn("Please login first.")
        pause()
        return

    show_art()
    print(f"{C_G}Welcome {state['user']}, is there anything that I can help?\n{C_RST}", flush=True)

    p_label("Enter recipient username (case-insensitive):")
    r = prompt().strip().lower()

    pem = fetch_pubkey(sock, r)

    if not pem:
        p_err("Recipient public key not found.")
        pause()
        return

    p_label("Enter message:")
    msg = prompt()

    try:
        payload = encrypt_message_rsa(msg, pem)
    except Exception as e:
        p_err(f"Encryption error: {e}")
        pause()
        return

    send_json(sock, {"action": "send", "recipient": r, "payload": payload})

    resp = recv_json_line(sock)

    if resp and resp.get("ok"):
        p_ok(f"Message stored. id: {resp.get('message_id')}")
    else:
        p_err(f"Send failed: {None if not resp else resp.get('msg')}")

    pause()


def do_check(sock, state):
    if not state.get("user"):
        p_warn("Please login first.")
        pause()
        return

    show_art()
    print(f"{C_G}Welcome {state['user']}, is there anything that I can help?{C_RST}", flush=True)

    send_json(sock, {"action": "list"})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Failed to fetch inbox: {None if not resp else resp.get('msg')}")
        pause()
        return

    inbox = resp.get("inbox", [])

    if not inbox:
        p_info("Inbox is empty.")
        pause()
        return

    print(f"{C_W}== Inbox of {state['user']} =={C_RST}", flush=True)

    for it in inbox:
        print(f"{C_C}{it['idx']}){C_RST} id={it['id']} from={it['from']} time={it['ts']}", flush=True)

    p_label("Pick a message number (blank to cancel):")
    ch = prompt().strip()

    if not ch:
        return

    try:
        idx = int(ch)
    except:
        p_err("Invalid number")
        pause()
        return

    send_json(sock, {"action": "get", "index": idx})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Failed to fetch message: {None if not resp else resp.get('msg')}")
        pause()
        return

    payload = resp["payload"]
    
    suggested = my_priv_path(state["user"])
    p_label(f"Enter path to YOUR PRIVATE KEY (PEM) to decrypt (e.g., {suggested}):")
    priv_path = prompt().strip()

    if not priv_path:
        p_warn("Cancelled.")
        pause()
        return

    if not os.path.isfile(priv_path):
        p_err(f"Private key file not found: {priv_path}")
        pause()
        return

    try:
        pt = decrypt_message_rsa(payload, priv_path)
    except Exception as e:
        p_err(f"Decryption error: {e}")
        pause()
        return

    print(f"{C_G}---- MESSAGE ----{C_RST}", flush=True)
    print(pt, flush=True)
    print(f"{C_G}-----------------{C_RST}", flush=True)

    pause()


def do_auth_test(sock, state):
    if not state.get("user"):
        p_warn("Please login first.")
        pause()
        return

    show_art()
    print(f"{C_G}Welcome {state['user']}, is there anything that I can help?{C_RST}", flush=True)

    send_json(sock, {"action": "challenge"})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Failed to get challenge: {None if not resp else resp.get('msg')}")
        pause()
        return

    nonce_b64 = resp["nonce_b64"]
    cid = resp["challenge_id"]

    print(f"{C_B}[*]{C_RST} Challenge ID: {cid}", flush=True)
    print(f"{C_B}[*]{C_RST} Nonce (base64): {nonce_b64}", flush=True)

    priv_path = my_priv_path(state["user"])

    if not os.path.isfile(priv_path):
        p_err(f"Private key file not found: {priv_path}")
        pause()
        return

    try:
        sig_b64 = sign_bytes_rsa(b64decode(nonce_b64), priv_path)
    except Exception as e:
        p_err(f"Signing error: {e}")
        pause()
        return

    send_json(sock, {"action": "prove", "challenge_id": cid, "signature_b64": sig_b64})
    resp = recv_json_line(sock)

    if resp and resp.get("ok"):
        p_ok("Authentication success")
    else:
        p_err(f"Authentication failed: {None if not resp else resp.get('msg')}")

    pause()


def do_upload_plugin(sock, state):
    if not state.get("user"):
        p_warn("Please login first.")
        pause()
        return

    show_art()
    print(f"{C_G}Welcome {state['user']}, is there anything that I can help?{C_RST}", flush=True)

    p_label("Enter plugin name:")
    name = prompt().strip()

    p_label("Enter PDF path to upload:")
    path = prompt().strip()

    if not os.path.isfile(path):
        p_err("File not found.")
        pause()
        return

    priv_path = my_priv_path(state["user"])

    if not os.path.isfile(priv_path):
        p_err(f"Private key not found: {priv_path}")
        pause()
        return

    with open(path, "rb") as f:
        file_bytes = f.read()

    p_info(f"Signing PDF using {priv_path}")

    try:
        sig_b64 = sign_bytes_rsa(file_bytes, priv_path)
    except Exception as e:
        p_err(f"Signing error: {e}")
        pause()
        return

    send_json(
        sock,
        {
            "action": "upload_plugin",
            "plugin_name": name,
            "pdf_b64": base64.b64encode(file_bytes).decode(),
            "sig_b64": sig_b64,
        },
    )

    resp = recv_json_line(sock)

    if resp and resp.get("ok"):
        p_ok(f"Uploaded plugin id={resp.get('plugin_id')}")
    else:
        p_err(f"Upload failed: {None if not resp else resp.get('msg')}")

    pause()


def do_list_plugins(sock, state):
    if not state.get("user"):
        p_warn("Please login first.")
        pause()
        return

    show_art()
    print(f"{C_G}Welcome {state['user']}, is there anything that I can help?{C_RST}", flush=True)

    send_json(sock, {"action": "list_plugins"})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Failed to fetch updates: {None if not resp else resp.get('msg')}")
        pause()
        return

    items = resp.get("plugins", [])

    if not items:
        p_info("No plugin updates yet.")
        pause()
        return

    print(f"{C_W}== Plugin Updates =={C_RST}", flush=True)

    for it in items:
        print(f"{C_C}{it['id']}){C_RST} {it['name']}  by {it['author']}  key={it['key_fpr']}", flush=True)

    p_label("Pick a plugin id to download (blank to cancel):")
    ch = prompt().strip()

    if not ch:
        return

    try:
        pid = int(ch)
    except:
        p_err("Invalid id")
        pause()
        return

    send_json(sock, {"action": "plugin_challenge", "plugin_id": pid})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Failed to start verification: {None if not resp else resp.get('msg')}")
        pause()
        return

    nonce_b64 = resp["nonce_b64"]
    cid = resp["challenge_id"]

    priv_path = my_priv_path(state["user"])

    if not os.path.isfile(priv_path):
        p_err(f"Private key not found: {priv_path}")
        pause()
        return

    p_info(f"Authorizing download by signing server nonce with {priv_path}")

    try:
        sig_b64 = sign_bytes_rsa(b64decode(nonce_b64), priv_path)
    except Exception as e:
        p_err(f"Signing error: {e}")
        pause()
        return

    send_json(sock, {"action": "plugin_download", "challenge_id": cid, "signature_b64": sig_b64})
    resp = recv_json_line(sock)

    if not resp or not resp.get("ok"):
        p_err(f"Download refused: {None if not resp else resp.get('msg')}")
        pause()
        return

    plug = resp["plugin"]
    data_b64 = resp["file_b64"]
    dev_sig_b64 = resp["dev_signature_b64"]
    sha_hex_srv = resp.get("sha256", "")

    file_bytes = base64.b64decode(data_b64)

    print(f"{C_B}[*]{C_RST} Developer: {plug['author']}", flush=True)

    p_label("Enter path to DEVELOPER'S PUBLIC KEY (PEM) to verify (e.g., keys/<developer>/public.pem):")
    dev_pub_path = prompt().strip()

    if not dev_pub_path or not os.path.isfile(dev_pub_path):
        p_err("Developer public key file not found.")
        pause()
        return

    with open(dev_pub_path, "r", encoding="utf-8") as f:
        dev_pub_pem = f.read()

    fpr_full = key_fingerprint_hex(dev_pub_pem)
    print(f"{C_B}[*]{C_RST} Developer key fingerprint (from your provided PEM): {fpr_full}", flush=True)

    print(f"{C_B}[*]{C_RST} Computing SHA-256 of received file...", flush=True)

    sha_local = hashlib.sha256(file_bytes).hexdigest()

    print(f"{C_W}    local : {sha_local}{C_RST}", flush=True)
    print(f"{C_W}    server: {sha_hex_srv}{C_RST}", flush=True)

    if sha_hex_srv and sha_local != sha_hex_srv:
        p_err("SHA-256 mismatch. File will not be saved.")
        pause()
        return
    else:
        p_ok("SHA-256 matches")

    print(f"{C_B}[*]{C_RST} Verifying developer signature with your provided public key...", flush=True)

    ok = verify_bytes_sig_rsa(file_bytes, dev_sig_b64, dev_pub_pem)

    if not ok:
        p_err("Developer signature verification FAILED. File will not be saved.")
        pause()
        return

    p_ok("Developer signature is valid")

    ensure_dir(DOWNLOADS_DIR)

    out_path = os.path.join(
        DOWNLOADS_DIR,
        f"{plug['name']}_id{plug['id']}.pdf".replace(" ", "_"),
    )

    with open(out_path, "wb") as f:
        f.write(file_bytes)

    p_ok(f"Verified and saved to: {out_path}")

    pause()


def main():
    state = {"user": None}

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        hello = recv_json_line(sock)

        if hello:
            p_info(hello.get("msg"))

        while True:
            if not state["user"]:
                show_art()

                print(f"{C_W}1){C_RST} Register", flush=True)
                print(f"{C_W}2){C_RST} Login", flush=True)
                print(f"{C_W}3){C_RST} Quit", flush=True)

                c = prompt().strip()

                if c == "1":
                    do_register(sock)

                elif c == "2":
                    do_login(sock, state)

                elif c == "3":
                    send_json(sock, {"action": "quit"})
                    _ = recv_json_line(sock)
                    p_info("Bye.")
                    break

                else:
                    p_warn("Invalid menu")
                    pause()

            else:
                show_art()

                print(f"{C_G}Welcome {state['user']}, is there anything that I can help?{C_RST}\n", flush=True)

                print(f"{C_W}1){C_RST} Send message", flush=True)
                print(f"{C_W}2){C_RST} Check mail", flush=True)
                print(f"{C_W}3){C_RST} Auth test (sign challenge)", flush=True)
                print(f"{C_W}4){C_RST} Upload plugin (PDF, signed)", flush=True)
                print(f"{C_W}5){C_RST} See updates from plugin developers", flush=True)
                print(f"{C_W}6){C_RST} Logout", flush=True)
                print(f"{C_W}7){C_RST} Quit", flush=True)

                c = prompt().strip()

                if c == "1":
                    do_send(sock, state)

                elif c == "2":
                    do_check(sock, state)

                elif c == "3":
                    do_auth_test(sock, state)

                elif c == "4":
                    do_upload_plugin(sock, state)

                elif c == "5":
                    do_list_plugins(sock, state)

                elif c == "6":
                    send_json(sock, {"action": "logout"})
                    _ = recv_json_line(sock)
                    state["user"] = None
                    p_info("Logged out")
                    pause()

                elif c == "7":
                    if state["user"]:
                        send_json(sock, {"action": "logout"})
                        _ = recv_json_line(sock)

                    send_json(sock, {"action": "quit"})
                    _ = recv_json_line(sock)
                    p_info("Bye.")
                    break

                else:
                    p_warn("Invalid menu")
                    pause()


if __name__ == "__main__":
    main()
