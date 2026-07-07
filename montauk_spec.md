---
title: "The Montauk Protocol"
author: "Manuel Rodriguez (manuel.rodriguez@teknios.tech)"
version: "0.2.0-draft"
status: "Draft Specification"
date: "2026-07-01"
---

# The Montauk Protocol

## Abstract

The Montauk Protocol enables secure, private peer-to-peer connections over IPv6 by using cryptographically generated rotating network addresses. Two parties sharing a secret can independently compute identical connection endpoints, while unauthorized parties face a computationally infeasible search space. The protocol provides connection privacy, mutual authentication, forward secrecy, and granular access control without requiring centralized infrastructure.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Overview](#3-protocol-overview)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Data Structures](#5-data-structures)
6. [Address Generation](#6-address-generation)
7. [Message Formats](#7-message-formats)
8. [Protocol Flows](#8-protocol-flows)
9. [Broker Protocol](#9-broker-protocol)
10. [State Machines](#10-state-machines)
11. [Security Considerations](#11-security-considerations)
12. [Implementation Requirements](#12-implementation-requirements)
13. [Test Vectors](#13-test-vectors)
14. [References](#14-references)

---

## 1. Introduction

### 1.1 Motivation

Current internet architecture assumes static or discoverable network addresses. This creates inherent security challenges:

- **Scannable attack surface**: Services bound to known addresses can be enumerated and probed
- **Targeted attacks**: Known addresses enable focused denial-of-service and exploitation attempts
- **Metadata exposure**: Connection endpoints reveal relationship information

IPv6's vast address space is typically viewed as an addressing solution. The Montauk Protocol repurposes it as a security mechanism: by computing connection addresses from shared secrets, legitimate peers can find each other while unauthorized parties face an infeasible search space. A host only controls the bits below its delegated routing prefix, but even confined to a single known /64 prefix, an attacker must search 2^64 addresses—each combined with roughly 2^16 candidate ports—per time bucket.

### 1.2 Design Goals

1. **Zero unauthorized attack surface**: Non-participants cannot discover or connect to services
2. **No centralized infrastructure**: Direct peer-to-peer connections without intermediaries
3. **Mutual authentication**: Both parties verify each other's identity
4. **Forward secrecy**: Compromise of long-term keys does not expose past communications
5. **Granular revocation**: Access can be revoked per-service or per-relationship
6. **NAT compatibility**: Participants behind NAT can use brokers without sacrificing end-to-end security

### 1.3 Scope

This specification defines:

- Cryptographic operations for key agreement and address generation
- Message formats for connection establishment
- Protocol flows for direct and brokered connections
- Broker architecture for NAT traversal
- Security requirements and threat model

This specification does not define:

- Application-layer protocols carried over established connections
- Key management user interfaces
- Router/firewall integration specifics (implementation-dependent)

---

## 2. Terminology

### 2.1 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 2.2 Definitions

**Address Stream**: The sequence of (IPv6 address, port) tuples generated over time for one direction of a relationship (one party acting as responder).

**Broker**: A server that facilitates connections between NAT-blocked participants.

**Direct Participant**: A participant with globally routable IPv6 connectivity.

**Guest Prior**: A semi-public Prior used for initial contact with a broker.

**Handshake Password**: A pre-shared key used in the Noise handshake, distinct from the Prior.

**Initiator**: The party initiating a connection.

**Prior**: Shared entropy used in session key derivation, establishing a unique relationship context.

**Relationship**: A bidirectional association between two participants, comprising shared cryptographic material and configuration.

**Responder**: The party accepting a connection.

**Routing Prefix**: The high-order bits of a participant's IPv6 addresses, fixed by network delegation. Generated addresses vary only in the bits below the prefix.

**Service**: An application endpoint accessible through a relationship.

**Session Key**: Derived key material used for address generation and authentication.

**Time Bucket**: A discrete time interval used for address computation.

**Valid Set**: The set of (address, port) tuples currently valid for incoming connections.

---

## 3. Protocol Overview

### 3.1 Conceptual Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     Relationship Establishment                   │
│                        (Out-of-band exchange)                    │
│                                                                  │
│   Alice and Bob exchange:                                        │
│   - Public keys                                                  │
│   - Prior                                                        │
│   - Handshake password                                           │
│   - Reachability information                                     │
│   - Service definitions                                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Address Computation                         │
│                                                                  │
│   Both parties independently compute:                            │
│   1. Shared secret (ECDH)                                        │
│   2. Session key (HKDF with Prior)                               │
│   3. Address stream (HMAC with time bucket)                      │
│                                                                  │
│   Result: Identical (address, port) at any given time            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Connection                                │
│                                                                  │
│   1. Initiator connects to computed (address, port)              │
│   2. Responder's firewall accepts (address in valid set)         │
│   3. Noise IKpsk2 handshake                                      │
│   4. Encrypted channel established                               │
│   5. Traffic proxied to internal service                         │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Participants

A Montauk deployment consists of:

1. **Montauk Server**: Manages relationships, computes addresses, handles connections
2. **Router/Firewall**: Filters traffic based on valid set
3. **Internal Services**: Application endpoints (SSH, HTTP, etc.)
4. **Client Devices**: User devices that authenticate to the Montauk Server

### 3.3 Connection Types

| Type     | Description                                                    |
| -------- | -------------------------------------------------------------- |
| Direct   | Both participants have IPv6; connect via computed addresses    |
| Brokered | One or both participants behind NAT; broker bridges connection |

---

## 4. Cryptographic Primitives

### 4.1 Key Agreement: X25519

All key agreement uses X25519 (RFC 7748).

**Key Generation**:

```
private_key = random_bytes(32)
public_key = X25519(private_key, 9)  # 9 is the basepoint
```

**Shared Secret**:

```
shared_secret = X25519(my_private_key, their_public_key)
```

The shared secret is 32 bytes. Implementations MUST validate that the result is not the all-zero value.

### 4.2 Key Derivation: HKDF-SHA256

Key derivation uses HKDF (RFC 5869) with SHA-256.

**Session Key Derivation**:

```
session_key = HKDF-SHA256(
    IKM = shared_secret,
    salt = prior,
    info = "montauk-v1-session",
    L = 32
)
```

### 4.3 Pseudorandom Function: HMAC-SHA256

Address generation and other PRF operations use HMAC-SHA256 (RFC 2104).

### 4.4 Authenticated Encryption: Noise Protocol

Connection establishment uses the Noise Protocol Framework (revision 34) with pattern IKpsk2:

```
IKpsk2:
    <- s
    ...
    -> e, es, s, ss
    <- e, ee, se, psk
```

Cipher suite: `Noise_IKpsk2_25519_ChaChaPoly_SHA256`

- DH: X25519
- Cipher: ChaCha20-Poly1305
- Hash: SHA256

The PSK is the handshake_password from the relationship.

### 4.5 Constants

| Constant        | Value                | Description                             |
| --------------- | -------------------- | --------------------------------------- |
| VERSION_STRING  | "montauk-v1"         | Protocol version identifier             |
| SESSION_INFO    | "montauk-v1-session" | HKDF info for session key               |
| ADDRESS_INFO    | "montauk-v1-address" | Domain separator for address generation |
| BUCKET_DURATION | 300                  | Time bucket duration in seconds         |
| PORT_MIN        | 1024                 | Minimum generated port                  |
| PORT_RANGE      | 64511                | Port range (1024 to 65534)              |

---

## 5. Data Structures

### 5.1 Public Key

```
PublicKey := BYTES[32]
```

A 32-byte X25519 public key.

### 5.2 Prior

```
Prior := BYTES[32]
```

32 bytes of entropy shared between relationship participants.

### 5.3 Handshake Password

```
HandshakePassword := BYTES[32]
```

32 bytes used as PSK in Noise handshake.

### 5.4 Reachability

```
IPv6Prefix := {
    prefix: BYTES[16],    # High `length` bits significant, remaining bits zero
    length: UINT8         # Prefix length P in bits (0-128)
}

Reachability := {
    type: UINT8,                       # 0x01 = DIRECT, 0x02 = BROKERED
    prefix: IPv6Prefix | NULL,         # Participant's routing prefix (DIRECT)
    broker_pubkey: PublicKey | NULL,
    broker_prefix: IPv6Prefix | NULL,  # Broker's routing prefix (BROKERED)
    broker_guest_prior: Prior | NULL
}
```

| Type Value | Meaning                                         | Required Fields                                  |
| ---------- | ----------------------------------------------- | ------------------------------------------------ |
| 0x01       | DIRECT - Participant has globally routable IPv6 | prefix                                           |
| 0x02       | BROKERED - Participant uses a broker            | broker_pubkey, broker_prefix, broker_guest_prior |

The routing prefix constrains address generation (Section 6.3): generated addresses must fall within a prefix that actually routes to the responder.

### 5.5 Service Definition

```
ServiceDefinition := {
    service_id: BYTES[16],    # UUID
    name: UTF8_STRING,        # Human-readable name
    protocol: UINT8,          # 0x01 = TCP, 0x02 = UDP
    internal_target: UTF8_STRING  # "host:port"
}
```

### 5.6 Relationship

```
Relationship := {
    relationship_id: BYTES[16],   # UUID
    peer_pubkey: PublicKey,
    prior: Prior,
    handshake_password: HandshakePassword,
    reachability: Reachability,
    services: [ServiceDefinition],
    created_at: UINT64,           # Unix timestamp
    revoked_at: UINT64 | NULL     # Unix timestamp or NULL
}
```

### 5.7 Valid Set Entry

```
ValidSetEntry := {
    address: BYTES[16],       # IPv6 address
    port: UINT16,
    relationship_id: BYTES[16],
    service_id: BYTES[16],
    valid_from: UINT64,       # Unix timestamp
    valid_until: UINT64       # Unix timestamp
}
```

---

## 6. Address Generation

### 6.1 Time Bucket Computation

```
T(timestamp) = floor(timestamp / BUCKET_DURATION)
```

Where `timestamp` is a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).

### 6.2 Session Key Derivation

Given a relationship between parties A and B:

```
shared_secret = X25519(A_private, B_public)
              = X25519(B_private, A_public)  # Same result

session_key = HKDF-SHA256(
    IKM = shared_secret,
    salt = prior,
    info = "montauk-v1-session",
    L = 32
)
```

### 6.3 Address Computation

A host does not control all 128 bits of its IPv6 address: the high bits are fixed by its delegated routing prefix, and only the bits below the prefix are locally assignable. Addresses are therefore generated within the responder's advertised prefix (Section 5.4).

For a given time bucket T:

```
input = T || ADDRESS_INFO || responder_pubkey
raw = HMAC-SHA256(session_key, input)

suffix = raw[0:16] AND NOT prefix_mask(P)
ipv6_address = responder_prefix OR suffix
port_raw = (raw[16] << 8) | raw[17]
port = PORT_MIN + (port_raw mod PORT_RANGE)
```

Where:

- `T` is encoded as UINT64 big-endian (8 bytes)
- `ADDRESS_INFO` is the UTF-8 encoding of "montauk-v1-address"
- `responder_pubkey` is the static public key (32 bytes) of the party that will accept the connection; its inclusion gives each direction of a relationship an independent address stream (Section 6.5)
- `||` denotes concatenation
- `responder_prefix` is the responder's advertised routing prefix: 16 bytes with all bits below the prefix length set to zero
- `P` is the advertised prefix length in bits; `prefix_mask(P)` is the 128-bit mask with the high P bits set
- `AND`, `OR`, `NOT` are bitwise operations over 128 bits
- `raw[0:16]` is the first 16 bytes; `raw[16]` and `raw[17]` are individual bytes

The responder MUST ensure the advertised prefix actually routes to it (typically by advertising the /64 of the network segment the Montauk Server occupies). A shorter prefix leaves more derived bits and therefore a larger unauthorized search space (Section 11.2).

### 6.4 Address Window

To accommodate clock drift, implementations SHOULD maintain a window of valid addresses:

```
current_T = T(now)
valid_addresses = [
    compute_address(session_key, responder_pubkey, responder_prefix, current_T - 1),
    compute_address(session_key, responder_pubkey, responder_prefix, current_T),
    compute_address(session_key, responder_pubkey, responder_prefix, current_T + 1)
]
```

This provides tolerance of ±BUCKET_DURATION seconds (±5 minutes with default settings).

### 6.5 Directionality

The session key (Section 6.2) is symmetric, but address computation is role-separated: the responder's static public key is part of the HMAC input, and the resulting address lies within that responder's routing prefix. Each direction of a relationship therefore has an independent address stream. The **responder** binds to addresses from its own stream; the **initiator** connects to them.

For bidirectional relationships where either party may initiate:

- Each party binds to the address stream derived from its own public key and prefix (its role as responder)
- Each party connects to the peer's address stream when initiating

Without this role separation, both directions would derive identical (address, port) values from the symmetric session key and collide.

---

## 7. Message Formats

### 7.1 Framing

All protocol messages are carried over the transport stream as length-prefixed frames:

```
Frame := {
    length: UINT16,       # Body length in bytes, big-endian
    body: BYTES[length]
}
```

One frame carries exactly one message: the FirstPacket, a Noise handshake message, or a Noise transport message. Noise messages are at most 65535 bytes, so any message fits in a single frame. Receivers MUST NOT process a frame body until `length` bytes have been received.

### 7.2 First Packet

The initial message from initiator to responder, carried as the body of the first frame:

```
FirstPacket := {
    version: UINT8,           # Protocol version (0x01)
    timestamp: UINT64,        # Unix timestamp, big-endian
    nonce: BYTES[16],         # Random nonce
    payload: BYTES[...]       # Noise handshake message
}
```

**Wire Format** (offsets relative to the start of the frame body):

```
Offset  Size  Field
0       1     version
1       8     timestamp (big-endian)
9       16    nonce
25      ...   payload (Noise message)
```

Total header size: 25 bytes. The payload extends to the end of the frame body.

### 7.3 Subsequent Packets

After the first packet, every frame body is a single Noise protocol message:

```
SubsequentPacket := {
    payload: BYTES[...]   # Noise handshake or transport message
}
```

### 7.4 Service Selection

After Noise handshake completes, if multiple services are available, the initiator sends:

```
ServiceRequest := {
    service_id: BYTES[16]    # UUID of requested service
}
```

This message is sent through the established encrypted channel.

### 7.5 Broker Messages

Broker messages are sent through the encrypted channel established between client (or guest) and broker.

#### 7.5.1 Registration Request (Client → Broker)

```
BrokerRegister := {
    type: UINT8,              # 0x01 = REGISTER
    client_pubkey: PublicKey,
    auth_count: UINT16,       # Number of authorization entries, big-endian
    authorizations: [PublicKey]  # auth_count pubkeys allowed to reach this client
}
```

#### 7.5.2 Connect Request (Client → Broker)

```
BrokerConnect := {
    type: UINT8,              # 0x02 = CONNECT
    target_pubkey: PublicKey  # Who the client wants to reach
}
```

#### 7.5.3 Broker Response

```
BrokerResponse := {
    type: UINT8,              # Response type
    payload: BYTES[...]       # Type-dependent payload
}
```

| Type | Meaning            | Payload                    |
| ---- | ------------------ | -------------------------- |
| 0x10 | REGISTERED         | Empty                      |
| 0x11 | WAITING            | Empty                      |
| 0x12 | MATCHED            | Empty (bridge established) |
| 0x20 | ERROR_UNAUTHORIZED | Empty                      |
| 0x21 | ERROR_NOT_FOUND    | Empty                      |
| 0x22 | ERROR_TIMEOUT      | Empty                      |

---

## 8. Protocol Flows

### 8.1 Relationship Establishment

Relationship establishment occurs out-of-band. Parties exchange:

1. Public keys (identity)
2. Prior (32 random bytes)
3. Handshake password (32 random bytes)
4. Reachability information (including the routing prefix)
5. Service definitions

Exchange methods (not specified by this protocol):

- QR code scan
- NFC tap
- Verbal passphrase (decoded to bytes via BIP-39 or similar)
- Secure messaging channel

### 8.2 Direct Connection

```
Initiator                                         Responder
    |                                                  |
    |  [Compute (address, port) for current T]         |
    |                                                  |
    |  [Router has (address, port) in valid set]       |
    |                                                  |
    |------------------ TCP SYN ---------------------->|
    |<----------------- TCP SYN-ACK ------------------|
    |------------------ TCP ACK ---------------------->|
    |                                                  |
    |  FirstPacket {                                   |
    |    version: 0x01,                                |
    |    timestamp: now,                               |
    |    nonce: random(16),                            |
    |    payload: Noise IK message 1                   |
    |  }                                               |
    |------------------------------------------------->|
    |                                                  |
    |                    [Validate timestamp window]   |
    |                    [Check nonce not replayed]    |
    |                    [Process Noise message]       |
    |                                                  |
    |<-------------------------------------------------|
    |  SubsequentPacket {                              |
    |    payload: Noise IK message 2 + psk             |
    |  }                                               |
    |                                                  |
    |  [Handshake complete]                            |
    |  [Encrypted channel established]                 |
    |                                                  |
    |  ServiceRequest { service_id }                   |
    |------------------------------------------------->|
    |                                                  |
    |                    [Validate service access]     |
    |                    [Proxy to internal service]   |
    |                                                  |
    |<================== Encrypted Data ==============>|
    |                                                  |
```

### 8.3 Brokered Connection

```
NAT Client                    Broker                    NAT Client
(Initiator)                                            (Responder)
    |                           |                           |
    |  [Responder pre-registered with broker]               |
    |                           |                           |
    |                           |<-- Persistent connection --|
    |                           |                           |
    |  [Compute broker address]                             |
    |                           |                           |
    |------ TCP connect ------->|                           |
    |                           |                           |
    |  Noise handshake with broker                          |
    |<=========================>|                           |
    |                           |                           |
    |  BrokerConnect {                                      |
    |    target_pubkey: responder_pub                       |
    |  }                                                    |
    |-------------------------->|                           |
    |                           |                           |
    |                           |  [Check authorization]    |
    |                           |  [Find responder conn]    |
    |                           |                           |
    |                           |  BrokerResponse {         |
    |                           |    type: MATCHED          |
    |                           |  }                        |
    |<--------------------------|-------------------------->|
    |                           |                           |
    |  [Broker now bridges bytes bidirectionally]           |
    |                           |                           |
    |  End-to-end Noise handshake (through broker)          |
    |<======================================================>|
    |                           |                           |
    |  [Encrypted channel established]                      |
    |  [Broker sees only ciphertext]                        |
    |                           |                           |
```

### 8.4 Revocation

Revocation is local to the revoking party:

**Per-Service Revocation**:

1. Remove service from relationship's service list
2. Stop computing addresses for that service
3. Update valid set
4. Next connection attempt for that service fails

**Full Relationship Revocation**:

1. Set relationship.revoked_at = now
2. Stop computing all addresses for relationship
3. Update valid set
4. All connection attempts fail

Revocation takes effect immediately for new connections. Existing connections MAY be terminated or allowed to continue (implementation choice).

---

## 9. Broker Protocol

### 9.1 Broker Role

A broker facilitates connections for NAT-blocked participants. The broker:

- Maintains persistent connections from registered clients
- Accepts guest connections from initiators
- Bridges matched pairs
- Cannot decrypt end-to-end encrypted traffic

### 9.2 Broker Address Generation

Brokers use a two-tier address scheme:

**Client Addresses** (for registered clients):

```
session_key = HKDF(ECDH(broker_priv, client_pub), client_prior, ...)
address = compute_address(session_key, broker_pubkey, broker_prefix, T)
```

**Guest Addresses** (for initiators):

```
session_key = HKDF(ECDH(broker_priv, guest_pub), guest_prior, ...)
address = compute_address(session_key, broker_pubkey, broker_prefix, T)
```

The broker is the responder for these connections, so its public key and routing prefix enter the address computation (Section 6.3). The guest_prior and the broker's prefix are shared by clients when they share their reachability information.

### 9.3 Broker Authorization

Clients pre-authorize which public keys may reach them:

```
BrokerRegister {
    client_pubkey: client_pub,
    auth_count: N,
    authorizations: [allowed_pub_1, ..., allowed_pub_N]
}
```

The broker maintains an authorization table:

```
authorization_table[client_pubkey] = set(authorized_pubkeys)
```

Connection requests are checked:

```
if initiator_pubkey in authorization_table[target_pubkey]:
    allow
else:
    reject with ERROR_UNAUTHORIZED
```

### 9.4 Broker Security Properties

| Property                | Guarantee                                           |
| ----------------------- | --------------------------------------------------- |
| Traffic confidentiality | Broker sees only ciphertext (end-to-end encryption) |
| Client identity         | Broker knows client public keys                     |
| Relationship graph      | Broker knows who connects to whom                   |
| Traffic analysis        | Broker can observe timing and volume                |
| Impersonation           | Broker cannot impersonate clients (no private keys) |

### 9.5 Broker Redundancy

Clients MAY register with multiple brokers for redundancy. Initiators try brokers in order until connection succeeds.

---

## 10. State Machines

### 10.1 Server Connection State

```
                    ┌──────────────┐
                    │   LISTENING  │
                    └──────┬───────┘
                           │ TCP connection received
                           ▼
                    ┌──────────────┐
                    │   CONNECTED  │
                    └──────┬───────┘
                           │ FirstPacket received
                           ▼
                    ┌──────────────┐
         ┌─────────│  VALIDATING  │─────────┐
         │         └──────────────┘         │
         │ Invalid                          │ Valid
         ▼                                  ▼
  ┌──────────────┐                  ┌──────────────┐
  │   REJECTED   │                  │ HANDSHAKING  │
  └──────────────┘                  └──────┬───────┘
                                           │ Handshake complete
                                           ▼
                                   ┌──────────────┐
                                   │ ESTABLISHED  │
                                   └──────┬───────┘
                                          │ Close or error
                                          ▼
                                   ┌──────────────┐
                                   │    CLOSED    │
                                   └──────────────┘
```

### 10.2 Client Connection State

```
                    ┌──────────────┐
                    │     IDLE     │
                    └──────┬───────┘
                           │ Initiate connection
                           ▼
                    ┌──────────────┐
                    │  CONNECTING  │
                    └──────┬───────┘
                           │ TCP established
                           ▼
                    ┌──────────────┐
                    │ HANDSHAKING  │
                    └──────┬───────┘
          ┌────────────────┼────────────────┐
          │ Failure        │ Success        │
          ▼                ▼                │
   ┌──────────────┐ ┌──────────────┐        │
   │    FAILED    │ │ ESTABLISHED  │        │
   └──────────────┘ └──────┬───────┘        │
                           │ Close          │
                           ▼                │
                    ┌──────────────┐        │
                    │    CLOSED    │<───────┘
                    └──────────────┘
```

### 10.3 Broker State (Per Client)

```
                    ┌──────────────┐
                    │ UNREGISTERED │
                    └──────┬───────┘
                           │ BrokerRegister received
                           ▼
                    ┌──────────────┐
                    │  REGISTERED  │◄─────────────┐
                    └──────┬───────┘              │
                           │ BrokerConnect       │
                           │ for this client     │
                           ▼                     │
                    ┌──────────────┐             │
                    │   BRIDGING   │─────────────┘
                    └──────────────┘  Bridge closed
```

---

## 11. Security Considerations

### 11.1 Threat Model

**In Scope**:

- Network attackers (passive observation, active injection)
- Port scanners and service enumerators
- Denial of service attempts
- Replay attacks
- Man-in-the-middle attacks

**Out of Scope**:

- Endpoint compromise (malware on participant systems)
- Physical attacks
- Social engineering
- Quantum computers (protocol uses classical cryptography)

### 11.2 Security Properties

| Property                  | Mechanism                   | Notes                    |
| ------------------------- | --------------------------- | ------------------------ |
| Address unpredictability  | HMAC-SHA256 with secret key | 2^(128-P) addresses × ~2^16 ports per bucket within a known prefix (≈2^80 for a /64) |
| Connection authentication | Noise IKpsk2                | Mutual authentication    |
| Forward secrecy           | Ephemeral keys in Noise     | Per-session keys         |
| Replay protection         | Timestamp + nonce           | Window-based validation  |
| Traffic confidentiality   | ChaCha20-Poly1305           | Authenticated encryption |

### 11.3 Timestamp Validation

Servers MUST validate first packet timestamps:

1. Compute acceptable window: `[now - tolerance, now + tolerance]`
2. Reject packets outside window
3. Default tolerance: 30 seconds (RECOMMENDED), configurable per-relationship

### 11.4 Nonce Tracking

Servers MUST track recently seen nonces:

1. Maintain set of (nonce, timestamp) pairs
2. Reject packets with previously seen nonce
3. Expire entries older than tolerance window
4. Storage requirement: O(connections × tolerance / bucket_duration)

### 11.5 Silent Rejection

Servers MUST NOT send responses to invalid connection attempts:

- Invalid address: DROP (no response)
- Invalid timestamp: DROP (no response)
- Replayed nonce: DROP (no response)
- Failed handshake: close connection silently

This prevents attackers from distinguishing rejection reasons.

### 11.6 Rate Limiting

Implementations SHOULD implement rate limiting:

| Layer  | Mechanism                     | Recommended Limits   |
| ------ | ----------------------------- | -------------------- |
| Router | Per-source-IP packet rate     | 10 packets/second    |
| Server | Per-source-IP connection rate | 5 connections/minute |
| Server | Handshake timeout             | 5 seconds            |

### 11.7 Known Limitations

1. **Time synchronization required**: Participants must have loosely synchronized clocks
2. **IPv6 required**: Protocol requires IPv6 (directly or via broker)
3. **Initial exchange security**: Relationship security depends on initial exchange security
4. **Metadata at broker**: Brokers observe connection graph and traffic patterns
5. **No post-quantum security**: X25519 and current primitives are not quantum-resistant
6. **Prefix stability**: Generated addresses depend on the responder's advertised routing prefix; renumbering (e.g., a new ISP-delegated prefix) requires updating reachability information out-of-band

---

## 12. Implementation Requirements

### 12.1 Mandatory Features

Implementations MUST support:

- X25519 key generation and agreement
- HKDF-SHA256 key derivation
- HMAC-SHA256 address generation
- Noise_IKpsk2_25519_ChaChaPoly_SHA256 handshake
- Length-prefixed message framing (Section 7.1)
- Timestamp validation with configurable tolerance
- Nonce tracking and replay rejection
- Address window computation (current ±1 bucket)

### 12.2 Recommended Features

Implementations SHOULD support:

- Multiple concurrent relationships
- Multiple services per relationship
- Per-service revocation
- Broker protocol (client and/or server role)
- Rate limiting
- Connection logging (configurable)

### 12.3 Interoperability

For interoperability, implementations MUST:

- Use big-endian byte order for all multi-byte integers
- Use the exact constant strings specified (version, info strings)
- Follow the wire formats exactly as specified
- Pass all test vectors (Section 13)

---

## 13. Test Vectors

### 13.1 Key Generation

```
Input:
    seed = 0x0001020304050607 08090a0b0c0d0e0f
           1011121314151617 18191a1b1c1d1e1f

Output:
    private_key = 0x0001020304050607 08090a0b0c0d0e0f
                  1011121314151617 18191a1b1c1d1e1f

    public_key = 0x8f40c5adb68f25624ae5b214ea767a6e
                 c94d829d3d7b5e1ad1ba6f3e2138285f
```

### 13.2 Shared Secret

```
Input:
    alice_private = 0x77076d0a7318a57d 3c16c17251b26645
                    df4c2f87ebc0992a b177fba51db92c2a

    bob_public = 0xde9edb7d7b7dc1b4 d35b61c2ece43537
                 3f8343c85b78674d adfc7e146f882b4f

Output:
    shared_secret = 0x4a5d9d5ba4ce2de1 728e3bf480350f25
                    e07e21c947d19e33 76f09b3c1e161742
```

### 13.3 Session Key Derivation

```
Input:
    shared_secret = 0x4a5d9d5ba4ce2de1 728e3bf480350f25
                    e07e21c947d19e33 76f09b3c1e161742

    prior = 0xdeadbeefcafebabe 0123456789abcdef
            fedcba9876543210 baadf00ddeadbeef

Output:
    session_key = 0xcf9dfe21bf261783 7c0c50d8bb14555e
                  45e3d2023cedea4c e2ce0bfb48dde05e
```

### 13.4 Address Generation

```
Input:
    session_key = 0xcf9dfe21bf261783 7c0c50d8bb14555e
                  45e3d2023cedea4c e2ce0bfb48dde05e   # From Section 13.3
    responder_pubkey = bob_public                     # From Section 13.2
    responder_prefix = 2001:db8:1234:5678::/64        # P = 64
    timestamp = 1706295600  # 2024-01-26 19:00:00 UTC
    T = floor(1706295600 / 300) = 5687652  # 0x000000000056c964

Intermediate:
    input = 0x000000000056c964 || "montauk-v1-address" || bob_public
    raw = 0x63aaf0499a92bce9 27916876089566ee
          083c82e88fa71dd5 7648fc882320fd40

Output:
    ipv6_address = 2001:db8:1234:5678:2791:6876:895:66ee
    port = 3132   # port_raw = 0x083c = 2108; 1024 + (2108 mod 64511)
```

### 13.5 First Packet

```
Input:
    version = 0x01
    timestamp = 1706295600
    nonce = 0x000102030405060708090a0b0c0d0e0f
    payload = [Noise message bytes]

Output:
    frame_body = 0x01 || 0x0000000065b40130 || 0x000102030405060708090a0b0c0d0e0f || [payload]
    wire_format = UINT16(len(frame_body)) || frame_body
```

_Note: The Noise handshake payload in Section 13.5 requires a complete Noise implementation; a full handshake transcript vector will be added in version 1.0. All other vectors above are complete._

---

## 14. References

### 14.1 Normative References

- [RFC 2104] Krawczyk, H., Bellare, M., and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, February 1997.
- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 5869] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.
- [RFC 7748] Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves for Security", RFC 7748, January 2016.
- [NOISE] Perrin, T., "The Noise Protocol Framework", Revision 34, 2018.

### 14.2 Informative References

- [RFC 8446] Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018.
- [WIREGUARD] Donenfeld, J., "WireGuard: Next Generation Kernel Network Tunnel", NDSS 2017.
- [SIGNAL] Marlinspike, M. and T. Perrin, "The X3DH Key Agreement Protocol", 2016.

---

## Appendix A: Wire Format Summary

```
Frame (carries every message):
+----------+------------------+
|  Length  |       Body       |
| 2 bytes  |  length bytes    |
+----------+------------------+

FirstPacket (frame body, 25+ bytes):
+--------+----------------+------------------+------------------+
| Version|   Timestamp    |      Nonce       |     Payload      |
| 1 byte |    8 bytes     |    16 bytes      |   variable       |
+--------+----------------+------------------+------------------+

BrokerRegister:
+--------+------------------+------------+------------------+
|  Type  |  Client Pubkey   | Auth Count |  Authorizations  |
| 1 byte |    32 bytes      |  2 bytes   |   32*N bytes     |
+--------+------------------+------------+------------------+

BrokerConnect:
+--------+------------------+
|  Type  |  Target Pubkey   |
| 1 byte |    32 bytes      |
+--------+------------------+

BrokerResponse:
+--------+------------------+
|  Type  |     Payload      |
| 1 byte |    variable      |
+--------+------------------+
```

---

## Appendix B: Example Relationship Exchange (Informative)

A human-readable exchange format using BIP-39 words:

```
=== BOB'S MONTAUK CARD ===

Identity: witch collapse practice feed shame open despair creek road again
          ice close garden mountain hollow tide salmon orbit meadow crisp
          anchor ridge maple harvest

Prior: army observe practice letter achieve hunting cat chapter interest grab clinic evolve
       village caught narrow future raw human truly sock hospital clever orphan ability

Password: abandon abandon abandon abandon abandon abandon abandon abandon
          abandon abandon abandon abandon abandon abandon abandon abandon
          abandon abandon abandon abandon abandon about about about

Reachability: DIRECT, prefix 2001:db8:1234:5678::/64

Services: photos, chat
```

Each 24-word mnemonic encodes 256 bits—the public key, Prior, and handshake password respectively—sufficient for the protocol's security requirements.

---

## Appendix C: Changelog

### Version 0.2.0-draft (July 2026)

- Address generation now derives only the bits below the responder's advertised routing prefix; added IPv6Prefix to reachability information (a host cannot bind addresses outside its delegated prefix, so full-128-bit generation was unroutable)
- Bound the responder's static public key into the address HMAC input, giving each direction of a relationship an independent address stream (previously both directions derived identical colliding addresses)
- Restated the address-unpredictability claim as the searchable space within a known prefix (2^(128-P) × ~2^16 per bucket) instead of "2^128 address space"
- Added uniform 2-byte length framing for all stream messages (message boundaries were previously undefined)
- Added auth_count field to BrokerRegister (authorization list length was previously unparseable)
- Corrected the timestamp encoding in the First Packet test vector (0x65b3c790 → 0x65b40130) and the UTC comment in the address generation test vector (15:00 → 19:00)
- Filled in the session key and address generation test vectors (Sections 13.3–13.4); verified the key generation and shared secret vectors (Sections 13.1–13.2) against RFC 7748
- Expanded the Appendix B identity mnemonic to 24 words (a 32-byte public key does not fit in 12 words)
- Noted prefix stability as a known limitation

### Version 0.1.0-draft (January 2026)

- Initial draft specification
