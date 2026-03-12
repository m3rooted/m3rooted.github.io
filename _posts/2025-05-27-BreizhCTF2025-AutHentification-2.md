---
title: (English) BreizhCTF 2025 | Write-up - AutHentification 2 [Crypto]
date: 2025-05-27 22:38:00 +0700
categories: [Write-up]
tags: [CTF, Crypto, Coding, Python, English]

image:
  path: /assets/img/2025-05-23-BreizhCTF2025/logo.png

description: "My write-up for the BreizhCTF 2025 hard crypto challenge AutHentification 2, where I exploited a custom AES-GCM implementation bug (missing counter increment between encryption and tag generation), recovered the GHASH key in GF(2^128), forged a valid admin tag, and retrieved the flag"
---

## Skills Required

- Solid understanding of AES-GCM internals (GCTR, GHASH, tag construction).
- Familiarity with finite-field arithmetic in $GF(2^{128})$.
- Ability to model a cryptographic bug as algebraic equations.
- Practical scripting skills with Sage + Python requests.
- Comfort with cookie formatting/escaping edge cases in web apps.

## Skills Learned

- Why a single missing counter increment can break AEAD guarantees.
- How nonce reuse + known plaintext still leaks a reusable keystream.
- How to turn GHASH/tag equations into a polynomial root-finding problem.
- How to recover $H$ and forge a valid GCM tag without knowing the AES key.
- How to automate a full exploit chain end-to-end against a Flask app.

## Challenge Overview

This challenge is the sequel to AutHentification 1.
In part 1, tag verification was ignored.
In part 2, the server now checks authentication properly, so reusing any random tag no longer works.

Goal:

- Forge a valid cookie that decrypts to role super_admin.
- Access /admin and read the flag.

The token format is still:

```json
{"username": "<name>", "role": "<role>"}
```

and the app still uses a fixed all-zero IV.

## Source Enumeration

The important files are the same as before:

- server.py: routing and auth workflow.
- crypto.py: token generation and verification.
- gcm/gcm.py: custom AES-GCM intern implementation.

Relevant code in crypto.py:

```python
IV  = b"\x00"*IV_LEN

def build_token(key, username, role):
  gcm = GCM(key, IV)
  token = dumps({
    "username": username,
    "role": role
  }).encode()

  ct, tag = gcm.encrypt(token)
  return ";".join([ct.hex(), tag.hex()])

def verif_token(key, token):
  gcm = GCM(key, IV)
  ct, tag = [bytes.fromhex(a) for a in token.split(";")]
  pt, is_auth = gcm.decrypt(ct, tag)

  if loads(pt.decode())["role"] != "super_admin":
    return False

  if not is_auth:
    return False

  return True
```

Unlike challenge 1, is_auth is now checked.
So we must forge both ciphertext and a valid tag.

## Root Cause: Wrong Counter Usage In GCM

The core bug is in gcm.py.
In standard GCM (NIST SP 800-38D):

- Ciphertext uses GCTR with $inc32(J_0)$.
- Tag uses GCTR with $J_0$.

But the challenge code uses the same value J for both operations.

```python
# Algorithm 4: GCM-AE_K
def encrypt(self, P, A=b""):
  J = self.iv + b"\x00"*(CTR_LEN-1) + b"\x01"
  C = self.gctr(J, P)
  T = self.build_tag(C, A, J)
  return C, T

# Algorithm 5: GCM-AD_K
def decrypt(self, C, T, A=b""):
  J = self.iv + b"\x00"*(CTR_LEN-1) + b"\x01"
  P = self.gctr(J, C)
  TT = self.build_tag(C, A, J)
```

That means:

- first keystream block for encryption = $E_K(J_0)$
- masking value used in tag = same $E_K(J_0)$

So confidentiality and authentication become algebraically linked.

![GCM counter misuse diagram]({{ '/assets/img/2025-05-23-BreizhCTF2025/aut2-schema-gcm-vuln.png' | relative_url }})

## Turning It Into Equations

Let:

- $X = E_K(J_0)$
- $A$ = AAD (empty here)
- $C$ = ciphertext
- $H = E_K(0^{128})$ (GHASH subkey)

Then tag generation becomes:

$$
T = X + GHASH_H(A \parallel C \parallel len(A) \parallel len(C))
$$

Because $A = \epsilon$, if $C$ is split into blocks $(C_1, \dots, C_n)$:

$$
T = X + \left(C_1H^{n+1} + C_2H^n + \cdots + C_nH^2 + L\,H\right)
$$

with $L = len(A)\parallel len(C)$ in bits on 128 bits.

We can recover $X$ immediately from known plaintext:

$$
X = C_1 + P_1
$$

because encryption incorrectly starts GCTR at $J_0$ itself.

Now everything in the tag equation is known except $H$.
So we solve one polynomial equation over $GF(2^{128})$, recover candidate roots for $H$, and compute a forged tag for our chosen admin ciphertext.

## Practical Exploit Strategy

1. Reset DB (optional) and register a user with controlled username.
2. Login and get auth cookie: ct;tag.
3. Rebuild exact plaintext JSON to recover keystream and $X$.
4. Forge target plaintext with role super_admin and derive forged_ct.
5. Build polynomial equation from observed (ct, tag), solve for $H$.
6. Recompute a valid tag for forged_ct using recovered $H$.
7. Send forged cookie to /admin and extract flag.

In practice, the polynomial can have multiple roots.
The provided solver simply loops after reset-db until one unique root is found, which makes exploitation straightforward.

## Solver (Sage)

```python
# Tested with Sage 10.5
import os
os.environ.setdefault("TERM", "xterm-256color")

from pwn import xor
from json import dumps
import requests
load("gf.sage")

from sys import argv
if len(argv) != 2:
  print("usage: sage solve.sage <URL>")
  raise SystemExit(1)

URL = argv[1].rstrip("/")

def build_pt(username, role="guest"):
  return dumps({
    "username": username,
    "role": role
  })

# JSON length is 33 + len(username), choose len(username)=143 to align to 16-byte blocks.
username = "skilo" + "o" * (143 - len("skilo"))
pt = build_pt(username).encode()

while True:
  requests.get(f"{URL}/reset-db")

  headers = {"User-Agent": "solve-script"}
  data = {"username": username, "password": "a"}
  requests.post(f"{URL}/register", headers=headers, data=data, allow_redirects=False)
  r = requests.post(f"{URL}/login", headers=headers, data=data, allow_redirects=False)

  token = r.cookies["auth"].replace("\\073", ";").strip('"')
  ct, tag = map(bytes.fromhex, token.split(";"))

  # Recover keystream (same bug as part 1 still helps here)
  keystream = xor(ct, pt)

  target_pt = build_pt("skilooooo", "super_admin").encode()
  forged_ct = xor(target_pt, keystream[:len(target_pt)])

  # Build equation in GF(2^128):
  # tag = X + sum(C_i * H^(n-i+1)) + (lA||lC)*H
  lA = b"\x00" * 8
  lC = (int(len(ct) * 8)).to_bytes(8, "big")
  X = bytes_to_gf(keystream[:16])
  Cs = [bytes_to_gf(ct[i:i+16]) for i in range(0, len(ct), 16)]

  R.<H> = PolynomialRing(Fp)
  f = sum(Cs[i] * H**(len(Cs) - i + 1) for i in range(len(Cs)))
  l = bytes_to_gf(lA + lC)
  poly = bytes_to_gf(tag) - (X + f + l * H)

  roots = Ideal(poly).groebner_basis()[0].roots()
  if len(roots) != 1:
    continue

  H = roots[0][0]

  # Recompute valid tag for forged_ct
  lC2 = (int(len(forged_ct) * 8)).to_bytes(8, "big")
  Cs2 = [bytes_to_gf(forged_ct[i:i+16]) for i in range(0, len(forged_ct), 16)]
  f2 = sum(Cs2[i] * H**(len(Cs2) - i + 1) for i in range(len(Cs2)))
  l2 = bytes_to_gf(lA + lC2)
  forged_tag = gf_to_bytes(X + f2 + l2 * H)

  forged = forged_ct.hex() + ";" + forged_tag.hex()

  s = requests.Session()
  s.cookies.set("auth", '"' + forged.replace(";", "\\073") + '"')
  resp = s.get(f"{URL}/admin", headers=headers)

  if "BZHCTF{" in resp.text:
    print("BZHCTF{" + resp.text.split("BZHCTF{")[1].split("}")[0] + "}")
    break
```

## Field Helpers (gf.sage)

```python
P.<x> = PolynomialRing(GF(2))
f = x**128 + x**7 + x**2 + x + 1
Fp.<a> = GF(2**128, modulus=f)

def bytes_to_gf(b):
  bits = "".join(bin(bb)[2:].zfill(8) for bb in b)
  return Fp([int(bit) for bit in bits])

def gf_to_bytes(g):
  out = [str(a) for a in list(g)]
  out = ["".join(out[i:i+8]) for i in range(0, len(out), 8)]
  return bytes(int(v, 2) for v in out)
```

## Flag

```text
BZHCTF{encore_et_toujours_de_la_faute_du_stagiaire_350cd55e8bf628ea}
```

![Admin page containing the flag]({{ '/assets/img/2025-05-23-BreizhCTF2025/aut2.png' | relative_url }})

## Takeaways

1. AES-GCM is fragile when implemented manually: one missed inc32 is enough to break authenticity.
2. Reusing nonce/IV already weakens confidentiality; coupling it with implementation mistakes is catastrophic.
3. Even with tag verification enabled, incorrect GCM internals can still allow full forgery.
4. For production, use well-tested AEAD libraries and avoid custom crypto implementations.