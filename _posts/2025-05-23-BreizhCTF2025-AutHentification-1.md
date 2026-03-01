---
title: (English) BreizhCTF 2025 | Write-up - AutHentification 1 [Crypto]
date: 2025-05-23 22:38:00 +0700
categories: [Write-up]
tags: [CTF, Crypto, Coding, Python, English]

image:
  path: /assets/img/2025-05-23-BreizhCTF2025/logo.png

description: "My write-up for the BreizhCTF 2025 medium crypto challenge AutHentification 1, where I analyzed an AES-GCM misuse (fixed key/nonce and missing tag verification), treated it like a reusable stream cipher, recovered the keystream from a controllable user cookie, and forged a super_admin cookie to obtain the flag"
---

## Skills Required

- Basic understanding of symmetric cryptography (AES, nonce/IV, keystream).
- Familiarity with AES-GCM and the role of authentication tag verification.
- Understanding of CTR/stream-cipher XOR properties (ciphertext = plaintext XOR keystream).
- Ability to exploit known/chosen-plaintext conditions.
- Basic Python scripting for byte-wise XOR, JSON handling, and cookie forging.

## Skills Learned

- How AES-GCM misuse (fixed key/nonce + no tag check) enables practical forgery.
- How to recover a reusable keystream from controlled plaintext-ciphertext pairs.
- How to craft a forged cookie by injecting a custom JSON role (super_admin).
- Why AEAD integrity checks are as critical as encryption itself.
- How to automate the full exploit flow cleanly in a short solver script.

## Overview of the challenge

In this challenge, we interact with a web application that stores an authentication token in a cookie named `auth`.
Our objective is to access `/admin` as `super_admin` to retrieve the flag.

The token is built from JSON:

```json
{"username":"<name>","role":"<role>"}
```

and encrypted with a custom AES-GCM implementation.  
At first glance, AES-GCM should provide confidentiality and authenticity.  
However, two implementation mistakes make token forgery possible:

1. The IV/nonce is fixed to a constant value.
2. The authentication result returned by `decrypt` is ignored.

That turns the system into a reusable stream cipher where we can recover the keystream from known plaintext and then forge arbitrary roles.

## Exploit summary

```text
Exploit for 'Authentification 1' (Breizh CTF).
Bug chain:
1) App uses AES-GCM with a fixed IV (bad), BUT more importantly...
2) verif_token() ignores the authentication result from GCM.decrypt().
   It decrypts and parses JSON even when the tag is invalid.
Because GCM encryption uses CTR under the hood, we can:
- login once to get (ciphertext, tag)
- reconstruct the plaintext JSON
- derive the keystream = C xor P
- craft a new plaintext JSON with role="super_admin"
- compute forged ciphertext and reuse any 16-byte tag (ignored)
```

## Enumeration

From the provided source, the interesting files are:

- `server.py`: Flask routes (`/register`, `/login`, `/admin`, `/reset-db`).
- `crypto.py`: token generation and token verification.
- `gcm/gcm.py`: custom GCM implementation.

The login flow is:

1. Register a user (role is always `guest`).
2. Login and receive cookie `auth`.
3. `/admin` decrypts that cookie and checks if role is `super_admin`.

## Analyzing the source code

`crypto.py` defines a global fixed IV:

```python
IV  = b"\x00"*IV_LEN
```

Token creation:

```python
def build_token(key, username, role):
    gcm = GCM(key, IV)
    token = dumps({
        "username": username,
        "role": role
    }).encode()

    ct, tag = gcm.encrypt(token)
    return ";".join([ct.hex(), tag.hex()])
```

Token verification:

```python
def verif_token(key, token):
    gcm = GCM(key, IV)
    ct, tag = [bytes.fromhex(a) for a in token.split(";")]
    pt, is_auth = gcm.decrypt(ct, tag)

    if loads(pt.decode())["role"] != "super_admin":
        return False

    return True
```

The critical issue is obvious: `is_auth` is never checked.  
So even when tag verification fails, the function still parses plaintext and only checks `"role"`.

In `gcm/gcm.py`, decryption returns `(P, False)` on invalid tag:

```python
if TT != T:
    return (P, False)
```

but this status is discarded by `verif_token`.

Additionally, because `IV` is fixed and the key is the same during one session, encryption is effectively:

```text
C = P XOR KS
```

with a reusable keystream `KS`.

## Solution

Let:

- `P_user` be plaintext JSON for our own account (known because we choose username and role is `guest`).
- `C_user` be ciphertext part from the cookie we receive after login.

Then:

```text
C_user = P_user XOR KS
=> KS = C_user XOR P_user
```

Now choose a target plaintext:

```json
{"username":"skilooooo","role":"super_admin"}
```

Call it `P_admin`. We forge:

```text
C_admin = P_admin XOR KS
```

and send cookie:

```text
auth = hex(C_admin) ; hex(any_16_byte_tag)
```

We can simply reuse the original tag from our valid login cookie.  
Since authenticity is ignored, only the decrypted `"role"` matters.

## Exploitation script

The following script automates the attack:

```python
from pwn import xor
from json import dumps
import requests
from sys import argv

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def token_plaintext(username: str, role: str) -> bytes:
    # Must match server-side json.dumps default formatting.
    return json.dumps({"username": username, "role": role}).encode()


def forge_admin_cookie(auth_cookie: str, original_username: str, target_username: str) -> str:
    ct_hex, tag_hex = auth_cookie.split(";")
    ct = bytes.fromhex(ct_hex)

    p = token_plaintext(original_username, "guest")
    p2 = token_plaintext(target_username, "super_admin")

    if len(p) != len(ct):
        raise ValueError("Plaintext length does not match ciphertext length; json formatting mismatch?")
    if len(p2) != len(p):
        raise ValueError(
            f"Need same-length plaintexts for CTR bitflips (got {len(p)} vs {len(p2)}). "
            "Adjust username lengths."
        )

    keystream = xor_bytes(ct, p)
    forged_ct = xor_bytes(keystream, p2)
    return f"{forged_ct.hex()};{tag_hex}"


def main() -> None:
    if len(argv) != 2:
        print("usage: python template_authentification.py <URL>")
        print("example: python template_authentification.py http://archive.cryptohack.org:61277")
        raise SystemExit(2)

    url_base = argv[1].rstrip("/")

    session = requests.Session()
    session.headers.update({"User-Agent": "ctf-solver"})

    # Optional but makes reruns deterministic: resets key + users.
    session.get(f"{url_base}/reset-db", timeout=10)

    # Choose usernames so that resulting JSON length stays constant.
    # role: "guest" -> "super_admin" increases length by 6.
    target_username = "admin"
    original_username = target_username + ("A" * 6)
    password = "demo"

    # Register
    r = session.post(
        f"{url_base}/register",
        data={"username": original_username, "password": password},
        timeout=10,
    )
    # If MAX_USERS has already been hit and reset-db is disabled, this might 403.

    # Login (disable redirects to capture Set-Cookie)
    r = session.post(
        f"{url_base}/login",
        data={"username": original_username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    if "auth" not in r.cookies:
        raise RuntimeError(f"No auth cookie received (status={r.status_code}).")

    # Cookie values cannot safely contain ';', Werkzeug escapes it as octal \073.
    # requests gives us the escaped form, so normalize back to the token format.
    auth = r.cookies["auth"].strip('"').replace("\\073", ";")
    forged = forge_admin_cookie(auth, original_username, target_username)

    # Request /admin with forged cookie
    forged_cookie_value = forged.replace(";", "\\073")

    # Werkzeug only unescapes octal sequences (like \073 for ';') inside quoted values.
    # requests won't quote cookie values for us, so craft the Cookie header explicitly.
    admin_session = requests.Session()
    admin_session.headers.update({"User-Agent": "ctf-solver"})
    cookie_header = f'auth="{forged_cookie_value}"'

    r = admin_session.get(
        f"{url_base}/admin",
        headers={"Cookie": cookie_header},
        timeout=10,
    )
    print(r.text)


if __name__ == "__main__":
    main()
```

## Flag

Running the exploit returns the admin page containing the flag:

```text
BZHCTF{ne_jamais_re-utiliser_le_nonce_e1d6ce70d3d1018c}
```

![Admin page containing the flag]({{ '/assets/img/2025-05-23-BreizhCTF2025/aut1.png' | relative_url }})

## Getting the flag

1. Register and login with a controlled username to get one valid token.
2. Rebuild the exact JSON plaintext and recover keystream using XOR.
3. Forge a new ciphertext for a plaintext containing `"role": "super_admin"`.
4. Reuse any 16-byte tag (for example the original one) and send forged cookie to `/admin`.
5. Read the flag from the response.
