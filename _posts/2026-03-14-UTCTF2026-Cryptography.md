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

This challenge shows us the working of a Linear Congruential Generator (LCG) and exactly why it isn’t secure for cryptography. It is one of the oldest and most widely used algorithms for generating pseudorandom numbers.

File `lcg.txt`:

```text
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

{: file="lcg.txt" }

**Solution**

Before solving this problem, one needs only a basic understanding of group theory, particularly multiplicative inverses. In modular arithmetic modulo $m$, the inverse of an integer $p$ is an integer $q$ such that $pq \equiv 1 \pmod m$. With this concept, the analysis reduces to modular manipulations that allow recovery of $a$ and $c$.

The LCG algorithm operates based on a single calculation:

$$
X_{n+1} = (a \cdot X_n + c)\ (\mathrm{mod}\ m)
$$

Now that we have $a$, recovering $c$ is trivial.

$$
c \equiv x_2 - a \cdot x_1 \pmod m
$$

You might have noticed that we needed only 3 outputs to recover $a$ and $c$.

**Exploitation script**

```python
from pwn import *

m = 4294967296
x = [4176616824, 2681459949, 1541137174, 3272915523]
ct = bytes.fromhex("3cff226828ec3f743bb820352aff1b7021b81b623cff31767ad428672ef6") #ciphertext = ct

d1 = (x[1] - x[0]) % m
d2 = (x[2] - x[1]) % m

a = (d2 *pow(d1,-1,m)) % m
c = (x[1] - a * x[0]) % m
x5 = (a * x[3] + c) % m

print(xor(ct, x5.to_bytes(4, 'big')))
```

**Flag**

```text
utflag{pr3d1ct_th3_futur3_lcg}
```

## Oblivious Error

## Smooth Criminal

This challenge is based on the Discrete Logarithm Problem (DLP). To approach it, the key idea is to determine the exponent $a$ from the relation

$$
g^a \equiv h \quad (\mathrm{mod}\ p).
$$

Thus, the main task is to transform the given data into this form and then apply an appropriate method to solve for $a$.

File `dlp.txt`:

```text
The flag has been encoded as a secret exponent x, where:

  h = g^x mod p

Your job: find x. Convert it from integer to bytes to get the flag.

p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517
```

{: file="dlp.txt" }

**Solution**

