---
title: (English) UTCTF 2026 - Cryptography [Fortune Teller | Oblivious Error | Smooth Criminal]
date: 2026-03-14 00:00:00 +0007
categories: [Write-up]
tags: [CTF, Crypto, Coding, Python, English]

image:
  path: /assets/img/2026-03-14-UTCTF2026/ut0.png

description: "My write-up for the Verilicious medium crypto challenge, where I analyzed information leaks in PKCS#1 v1.5 padding, translated the samples into a Hidden Number Problem (HNP) instance, and leveraged that to successfully recover the flag m"
---

## Fortune Teller

This challenge shows us the working of a Linear Congruential Generator (LCG) and exactly why it isn’t secure for cryptography.

File `lcg.txt`:

```lcg
We're using a Linear Congruential Generator (LCG) defined as:

  x_(n+1) = (a * x_n + c) % m

where m = 4294967296 (2^32), and a and c are secret.

We intercepted the first 4 outputs of the generator:

  output_1 = 4176616824
  output_2 = 2681459949
  output_3 = 1541137174
  output_4 = 3272915523

The flag was encrypted by XORing it with output_5 (used as a 4-byte repeating key).

  ciphertext (hex) = 3cff226828ec3f743bb820352aff1b7021b81b623cff31767ad428672ef6
```

# Solution

The LCG algorithm operates based on a single calculation:
