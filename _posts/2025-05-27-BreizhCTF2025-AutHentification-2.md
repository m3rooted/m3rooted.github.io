---
title: (English) BreizhCTF 2025 | Write-up - AutHentification 2 [Crypto]
date: 2025-05-27 22:38:00 +0700
categories: [Write-up]
tags: [CTF, Crypto, Coding, Python, English]

image:
  path: /assets/img/2025-05-23-BreizhCTF2025/logo.png

description: "My write-up for the BreizhCTF 2025 medium crypto challenge AutHentification 1, where I analyzed an AES-GCM misuse (fixed key/nonce and missing tag verification), treated it like a reusable stream cipher, recovered the keystream from a controllable user cookie, and forged a super_admin cookie to obtain the flag"
---