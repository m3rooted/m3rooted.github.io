---
layout: post
title: "OSI Model: The 7-Layer Structure"
subtitle: "Roles, Functions, and Common Protocols"
category: blog
tags: networking osi fundamentals
titles_from_headings: false
---

The OSI (Open Systems Interconnection) model breaks networking into seven layers.
Each layer provides services to the one above it and relies on the one below it.
This post summarizes the purpose of each layer, common functions, and example
protocols or devices.

<!--more-->

* this unordered seed list will be replaced by the toc
{:toc}

## Overview

The OSI model is a conceptual framework that helps explain how data moves from
applications on one host to applications on another. It is useful for troubleshooting
and for mapping protocols, devices, and responsibilities to specific layers.

---

## OSI Layer Flow Diagram

```mermaid
flowchart LR
  subgraph A[Host A]
    A7[Layer 7: Application]
    A6[Layer 6: Presentation]
    A5[Layer 5: Session]
    A4[Layer 4: Transport]
    A3[Layer 3: Network]
    A2[Layer 2: Data Link]
    A1[Layer 1: Physical]
    A7 --> A6 --> A5 --> A4 --> A3 --> A2 --> A1
  end

  subgraph B[Host B]
    B7[Layer 7: Application]
    B6[Layer 6: Presentation]
    B5[Layer 5: Session]
    B4[Layer 4: Transport]
    B3[Layer 3: Network]
    B2[Layer 2: Data Link]
    B1[Layer 1: Physical]
    B1 --> B2 --> B3 --> B4 --> B5 --> B6 --> B7
  end

  A1 --- B1
```

## OSI Model: 7-Layer Structure

### Layer 7: Application

Closest to the user. This layer defines the network protocols that applications
use to communicate. It is not the application itself, but the services it uses.

**Common protocols:**

* HTTP: web access
* HTTPS: secure web access (TLS encryption)
* FTP: file transfer
* SMTP: send email
* POP3 / IMAP: receive email
* DNS: name resolution (domain name to IP)

**PDU:** Data

---

### Layer 6: Presentation

Acts like a translator. It makes sure data from one system can be read by
another system.

**Main functions:**

* Data formatting and translation
* Encryption and decryption
* Compression and decompression

**PDU:** Data

---

### Layer 5: Session

Manages conversations between applications on different hosts.

**Main functions:**

* Establish sessions
* Maintain sessions
* Synchronize with checkpoints
* Terminate sessions in an orderly way

**PDU:** Data

---

### Layer 4: Transport

Provides end-to-end delivery between applications. It can be reliable or
best-effort depending on the protocol.

**Main functions:**

* Segmentation and reassembly
* Port addressing (for example, TCP 443 for HTTPS)
* Connection-oriented or connectionless delivery
* Flow control
* Error detection and recovery (primarily with TCP)

**Common protocols:**

* TCP
* UDP

**PDU:** Segment

---

### Layer 3: Network

Moves packets across multiple networks (internetworking).

**Main functions:**

* Logical addressing with IP (IPv4 / IPv6)
* Routing and path selection (routers operate here)
* Packet fragmentation and reassembly when MTU limits apply

**Common protocols:**

* IP
* ICMP

**PDU:** Packet

---

### Layer 2: Data Link

Provides reliable node-to-node delivery on a local network segment.

**Main functions:**

* Framing (adds header and trailer to frames)
* MAC addressing (NIC hardware address)
* Media access control (who can transmit and when)
* Error detection (often via CRC)
* Flow control at the link level

**Common devices:**

* Switches (Layer 2)
* Bridges
* NICs

**PDU:** Frame

---

### Layer 1: Physical

Transmits raw bits over the physical medium and defines electrical and
mechanical characteristics.

**Main functions:**

* Media specifications (copper, fiber, wireless)
* Bit encoding into signals
* Data rates (bps)
* Bit synchronization
* Physical topology (star, bus, ring, mesh)
* Transmission modes (simplex, half-duplex, full-duplex)

**Common devices:**

* Hubs
* Repeaters
* Modems
* Cables and transceivers

**PDU:** Bit

---

## Quick Summary Table

| Layer | Name         | Primary Focus                | PDU     |
|------:|--------------|------------------------------|---------|
| 7     | Application  | User-facing network services | Data    |
| 6     | Presentation | Translation, encryption      | Data    |
| 5     | Session      | Session control              | Data    |
| 4     | Transport    | End-to-end delivery          | Segment |
| 3     | Network      | Routing and IP               | Packet  |
| 2     | Data Link    | Local delivery, MAC          | Frame   |
| 1     | Physical     | Signals and media            | Bit     |
