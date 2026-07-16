---
title: "The Montauk Protocol"
author: "Manuel Rodriguez (manuel.rodriguez@teknios.tech)"
version: "0.4.0-draft"
status: "Draft Specification"
date: "2026-07-09"
license: "CC BY 4.0 (test vectors: CC0 1.0)"
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

**Address Stream**: The sequence of (IPv6 address, port) tuples generated over time for one service offered by one party (the responder for that stream) within a relationship.

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

**Prologue**: The Noise prologue is the 25-byte FirstPacket header (version || timestamp || nonce), exactly as transmitted (Section 7.2). This binds the replay-protection fields to the handshake: a tampered or re-stamped header causes AEAD failure when the responder processes message 1, and the packet is dropped silently (Section 11.5).

**Handshake payloads**: For direct connections, both handshake message payloads MUST be zero-length. For brokered connections, the message 1 payload MUST be exactly the 16-byte service_id of the requested service (Section 7.4) and the message 2 payload MUST be zero-length. A receiver MUST abort the handshake silently on any other payload length.

### 4.5 Constants

| Constant        | Value                | Description                             |
| --------------- | -------------------- | --------------------------------------- |
| VERSION_STRING  | "montauk-v1"         | Protocol version identifier             |
| SESSION_INFO    | "montauk-v1-session" | HKDF info for session key               |
| ADDRESS_INFO    | "montauk-v1-address" | Domain separator for address generation |
| BUCKET_DURATION | 300                  | Time bucket duration in seconds         |
| PORT_MIN        | 1024                 | Minimum generated port                  |
| PORT_RANGE      | 64511                | Port range (1024 to 65534)              |
| BROKER_SERVICE_ID | 16 zero bytes      | service_id for broker rendezvous connections |

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

The routing prefix constrains address generation (Section 6.3): generated addresses must fall within a prefix that actually routes to the responder. Any prefix length is permitted; the length sets the size of the unauthorized search space, with the tradeoff detailed in Section 11.8.

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
input = T || ADDRESS_INFO || responder_pubkey || service_id
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
- `service_id` is the 16-byte identifier of the requested service (Section 5.5); connections to a broker's rendezvous endpoints use BROKER_SERVICE_ID (Section 4.5)
- `||` denotes concatenation
- `responder_prefix` is the responder's advertised routing prefix: 16 bytes with all bits below the prefix length set to zero
- `P` is the advertised prefix length in bits; `prefix_mask(P)` is the 128-bit mask with the high P bits set
- `AND`, `OR`, `NOT` are bitwise operations over 128 bits
- `raw[0:16]` is the first 16 bytes; `raw[16]` and `raw[17]` are individual bytes

The responder MUST ensure the advertised prefix actually routes to it (typically by advertising the /64 of the network segment the Montauk Server occupies). Any prefix length P (0–128) is permitted: a shorter prefix leaves more derived host bits and therefore a larger unauthorized search space, while a longer prefix still functions correctly with a smaller space. Section 11.8 gives the full size/concealment tradeoff.

On common IPv6 stacks, making the prefix locally deliverable (e.g. a Linux AnyIP `local` route) is *necessary but not sufficient* to bind an individual computed address: the listening socket must additionally opt in to binding a non-assigned address (`IPV6_FREEBIND`, or the equivalent non-local-bind facility). The route enables delivery; the socket option enables the bind. Implementations MUST bind computed addresses without requiring each to be provisioned as an interface address.

Each service in a relationship has its own address stream: the (address, port) tuple an initiator connects to identifies both the relationship and the service, so no in-band service selection is needed for direct connections (Section 7.4), and per-service revocation is enforced at the network layer (Section 8.4).

### 6.4 Address Window

To accommodate clock drift, implementations SHOULD maintain a window of valid addresses for each (relationship, service) pair:

```
current_T = T(now)
valid_addresses = [
    compute_address(session_key, responder_pubkey, responder_prefix, service_id, current_T - 1),
    compute_address(session_key, responder_pubkey, responder_prefix, service_id, current_T),
    compute_address(session_key, responder_pubkey, responder_prefix, service_id, current_T + 1)
]
```

This provides *address* tolerance of ±BUCKET_DURATION seconds. The **effective**
clock-skew tolerance for a connection is smaller: it is the intersection of this
address window and the FirstPacket timestamp window (§11.3), which defaults to
±30 seconds. So with default settings a connection tolerates roughly ±30 s of
skew, not ±5 minutes — the wide address window mainly ensures a listener is
already bound before its bucket becomes current.

### 6.5 Directionality

The session key (Section 6.2) is symmetric, but address computation is role-separated: the responder's static public key and the service identifier are part of the HMAC input, and the resulting address lies within that responder's routing prefix. Each direction of a relationship—and each service—therefore has an independent address stream. The **responder** binds to addresses from its own stream; the **initiator** connects to them.

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

The 25-byte header is the Noise prologue (Section 4.4). A version byte other than the version pinned at relationship establishment makes the packet invalid; it MUST be dropped silently (Section 11.5). Versions are never negotiated in-band.

### 7.3 Subsequent Packets

After the first packet, every frame body is a single Noise protocol message:

```
SubsequentPacket := {
    payload: BYTES[...]   # Noise handshake or transport message
}
```

### 7.4 Service Selection

There is no service selection message. For direct connections, the (address, port) tuple the initiator connected to identifies both the relationship and the service (Section 6.3); the responder proxies to that service's internal_target once the handshake completes.

For brokered connections, no address selects the service, so the initiator carries the 16-byte service_id as the payload of Noise handshake message 1 (Section 4.4).

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

#### 7.5.3 Accept (Client → Broker)

Sent on a freshly opened data connection to claim a match offer (Section 9.4):

```
BrokerAccept := {
    type: UINT8,              # 0x03 = ACCEPT
    match_id: BYTES[16]       # From the MATCH_OFFER being accepted
}
```

#### 7.5.4 Keepalive

A Noise transport message with a zero-length plaintext is a keepalive. Keepalives carry no data and MUST otherwise be ignored. The client SHOULD send a keepalive on its control connection every KEEPALIVE_INTERVAL (Section 9.4); the broker MUST answer each client keepalive with one keepalive of its own, which is not itself answered.

#### 7.5.5 Broker Response

```
BrokerResponse := {
    type: UINT8,              # Response type
    payload: BYTES[...]       # Type-dependent payload
}
```

| Type | Meaning            | Payload                                    |
| ---- | ------------------ | ------------------------------------------ |
| 0x10 | REGISTERED         | Empty                                      |
| 0x11 | WAITING            | Empty                                      |
| 0x12 | MATCHED            | Empty (bridge live after this message)     |
| 0x13 | MATCH_OFFER        | match_id: BYTES[16] (on control connection) |
| 0x20 | ERROR_UNAUTHORIZED | Empty                                      |
| 0x21 | ERROR_NOT_FOUND    | Empty                                      |
| 0x22 | ERROR_TIMEOUT      | Empty                                      |

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
    |                    [Prologue = header bytes]     |
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
    |                    [Verify peer static == relationship]
    |                    [Address identifies service]  |
    |                    [Proxy to internal service]   |
    |                                                  |
    |<================== Encrypted Data ==============>|
    |                                                  |
```

**Responder requirements:**

1. **Peer authentication binding**: The Noise handshake cryptographically
   authenticates the initiator's static key. The responder MUST verify that
   this key equals the relationship's `peer_pubkey` and silently close on
   mismatch (Section 11.5). Selecting the relationship by address and holding
   the correct PSK is not sufficient on its own to bind a connection to a
   specific peer identity.

2. **Service availability**: If the selected service's `internal_target` is
   unavailable, the responder MUST still complete the Noise handshake before
   closing the connection. Failing earlier would reveal endpoint liveness to an
   unauthenticated party; after the handshake, liveness is exposed only to the
   authenticated, authorized peer.

3. **Connection close**: End-of-stream is signaled with a TCP FIN, carried
   through the encrypted channel in each direction independently (half-close is
   permitted). Closing one direction MUST NOT force the other closed until it
   also reaches end-of-stream. Note this FIN is *not* cryptographically
   authenticated: an on-path attacker (or, for brokered connections, the broker)
   can truncate the stream, which the transport does not detect. Applications
   that require truncation detection MUST carry their own authenticated
   end-of-message marker.

### 8.3 Brokered Connection

```
NAT Client                    Broker                    NAT Client
(Initiator)                                            (Responder)
    |                           |                           |
    |  [Responder registered; persistent control conn]      |
    |                           |<==== control (Noise) ====>|
    |                           |                           |
    |  [Compute broker guest address for current T]         |
    |                           |                           |
    |------ TCP connect ------->|                           |
    |  Noise handshake (guest)  |                           |
    |<=========================>|                           |
    |                           |                           |
    |  BrokerConnect {                                      |
    |    target_pubkey: responder_pub                       |
    |  }                                                    |
    |-------------------------->|                           |
    |                           |                           |
    |                           |  [Check authorization]    |
    |                           |  [Generate match_id]      |
    |                           |                           |
    |  BrokerResponse {         |  BrokerResponse {         |
    |    type: WAITING          |    type: MATCH_OFFER,     |
    |  }                        |    payload: match_id      |
    |                           |  }                        |
    |<--------------------------|-------------------------->|
    |                           |                           |
    |                           |  [Responder opens a NEW   |
    |                           |   data connection]        |
    |                           |<------ TCP connect -------|
    |                           |  Noise handshake (client) |
    |                           |<=========================>|
    |                           |                           |
    |                           |  BrokerAccept {           |
    |                           |    match_id               |
    |                           |  }                        |
    |                           |<--------------------------|
    |                           |                           |
    |  BrokerResponse {         |  BrokerResponse {         |
    |    type: MATCHED          |    type: MATCHED          |
    |  }                        |  }                        |
    |<--------------------------|-------------------------->|
    |                           |                           |
    |  [Broker bridges the initiator connection and the     |
    |   data connection; control connection stays open]     |
    |                           |                           |
    |  End-to-end Montauk handshake through the bridge      |
    |  (framed FirstPacket, identical to direct)            |
    |<======================================================>|
    |                           |                           |
    |  [Encrypted channel established]                      |
    |  [Broker sees only ciphertext and cannot replay       |
    |   the handshake (header is prologue-bound)]           |
    |                           |                           |
```

The bridged byte stream is identical to a direct connection: the responder applies the same FirstPacket validation (timestamp, nonce, prologue) to bytes arriving over a bridge as to a direct socket, and the message 1 payload carries the service_id (Section 7.4).

### 8.4 Revocation

Revocation is local to the revoking party:

**Per-Service Revocation**:

1. Remove service from relationship's service list
2. Stop computing addresses for that service
3. Update valid set
4. Connection attempts to that service's tuples are silently dropped at the network layer

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

- Maintains a persistent control connection from each registered client
- Accepts guest connections from initiators
- Offers matches to responders and bridges accepted pairs over dedicated data connections (Section 9.4)
- Cannot decrypt or replay end-to-end traffic

### 9.2 Broker Address Generation

The broker is reachable at a rotating **rendezvous address**, computed like any
Montauk address (Section 6.3) but keyed from a shared, semi-public
**guest_prior** rather than a per-relationship secret. Both registering clients
and connecting initiators use it for initial contact; the broker binds it (AnyIP
+ firewall, as a responder) and rotates it each time bucket.

```
session_key = HKDF-SHA256(IKM = broker_pubkey, salt = guest_prior, info = SESSION_INFO)
address     = compute_address(session_key, broker_pubkey, broker_prefix, BROKER_SERVICE_ID, T)
```

The broker_pubkey, broker_prefix, and guest_prior are shared by clients in their
reachability information (Section 5.4). Because the guest_prior is semi-public,
the rendezvous address is unguessable to outsiders yet reachable by any holder
of a client's reachability card; a party's *identity* is then established by the
Noise link handshake to the broker (Section 8.3), not by reaching the address.

*Note:* earlier drafts specified per-party addresses derived from
`ECDH(broker_priv, party_pub)`. A broker cannot pre-bind such an address for an
initiator whose key it does not yet know, so a single shared rendezvous (above)
is used instead. Per-client rotating addresses, negotiated after a client has
registered, remain a possible refinement.

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

`initiator_pubkey` MUST be the static key the initiator **authenticated with**
in its Noise handshake to the broker (Section 8.3), not a value it asserts in a
message — otherwise a client could claim any identity and the authorization
check would be meaningless. Likewise `client_pubkey` at registration is the
key the client authenticated with. The broker's authorization is a first-line
filter; end-to-end security still rests on the initiator↔responder handshake
through the bridge, which the broker cannot read or replay.

### 9.4 Match Protocol and Timeouts

The control connection established at registration is never converted into a bridge. When an authorized BrokerConnect arrives for a registered client, the broker:

1. Generates a match_id: 16 bytes from a cryptographically secure RNG
2. Sends MATCH_OFFER { match_id } on the target's control connection and WAITING to the initiator
3. Waits up to DIAL_BACK_TIMEOUT for a new data connection that authenticates as the target and presents BrokerAccept { match_id }
4. Sends MATCHED to both the initiator connection and the data connection, then bridges the two byte streams until either side closes

match_id values are single-use and expire after DIAL_BACK_TIMEOUT. A BrokerAccept with an expired or unknown match_id, or from a connection not authenticated as the offered target, is answered with ERROR_NOT_FOUND. If the offer expires, the broker sends ERROR_TIMEOUT to the initiator.

Default timing and limits (all configurable):

| Parameter                | Default | Description                                    |
| ------------------------ | ------- | ---------------------------------------------- |
| KEEPALIVE_INTERVAL       | 25 s    | Client keepalive period on control connection  |
| CLIENT_DEAD_AFTER        | 75 s    | No traffic on control connection → unregister  |
| DIAL_BACK_TIMEOUT        | 10 s    | MATCH_OFFER validity window                    |
| CONNECT_TIMEOUT          | 30 s    | Initiator's overall brokered-connect budget    |
| BRIDGE_HANDSHAKE_TIMEOUT | 5 s     | End-to-end handshake deadline (Section 11.6)   |
| MAX_BRIDGES_PER_CLIENT   | 8       | Concurrent bridges per registered client       |
| MAX_PENDING_MATCHES      | 4       | Outstanding MATCH_OFFERs per client            |

Bridges have no idle timeout of their own: bridged traffic is opaque to the broker, so liveness is the endpoints' responsibility. A bridge is torn down when either side closes its connection.

### 9.5 Broker Security Properties

| Property                | Guarantee                                           |
| ----------------------- | --------------------------------------------------- |
| Traffic confidentiality | Broker sees only ciphertext (end-to-end encryption) |
| Client identity         | Broker knows client public keys                     |
| Relationship graph      | Broker knows who connects to whom                   |
| Traffic analysis        | Broker can observe timing and volume                |
| Impersonation           | Broker cannot impersonate clients (no private keys) |
| Handshake replay        | Broker cannot replay end-to-end handshakes (header is prologue-bound; timestamps expire) |
| Stream truncation       | Broker CAN truncate the relayed stream undetectably (TCP FIN is unauthenticated, §8.2) |

### 9.6 Broker Redundancy

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

### 10.3 Broker State

**Control connection (per client)**:

```
        ┌──────────────┐  BrokerRegister received  ┌──────────────┐
        │ UNREGISTERED │──────────────────────────►│  REGISTERED  │
        └──────────────┘                           └──────┬───────┘
               ▲              Disconnect or               │
               └───────── CLIENT_DEAD_AFTER ──────────────┘
```

The control connection never leaves REGISTERED while healthy; it receives MATCH_OFFERs but is never itself bridged.

**Match (per BrokerConnect)**:

```
  ┌───────────┐ MATCH_OFFER sent ┌───────────┐ BrokerAccept   ┌───────────┐
  │ REQUESTED │─────────────────►│  OFFERED  │───────────────►│ BRIDGING  │
  └───────────┘                  └─────┬─────┘  { match_id }  └─────┬─────┘
                                       │ DIAL_BACK_TIMEOUT          │ Either side
                                       ▼                            ▼ closes
                                 ┌───────────┐                ┌───────────┐
                                 │  EXPIRED  │                │  CLOSED   │
                                 └───────────┘                └───────────┘
```

Matches are independent objects keyed by match_id; each BRIDGING match owns one initiator connection and one data connection.

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
| Address unpredictability  | HMAC-SHA256 with secret key | 2^(128-P) addresses × ~2^16 ports per bucket within a known prefix (≈2^80 for a /64); scales with prefix size, see Section 11.8 |
| Connection authentication | Noise IKpsk2                | Mutual authentication    |
| Forward secrecy           | Ephemeral keys in Noise     | Per-session keys         |
| Replay protection         | Timestamp + nonce, bound via Noise prologue | Header tampering breaks the handshake (Section 4.4) |
| Traffic confidentiality   | ChaCha20-Poly1305           | Authenticated encryption |

### 11.3 Timestamp Validation

Servers MUST validate first packet timestamps:

1. Compute acceptable window: `[now - tolerance, now + tolerance]`
2. Reject packets outside window
3. Default tolerance: 30 seconds (RECOMMENDED), configurable per-relationship

Timestamp validity and address-bucket validity (Section 6.4) are **independent
checks with different tolerances**: the address window is ±BUCKET_DURATION
(±300 s default) while the timestamp window is ±30 s default. A packet can
therefore arrive on a still-valid previous- or next-bucket address yet be
rejected on its timestamp. Both checks MUST pass.

### 11.4 Nonce Tracking

Servers MUST track recently seen nonces:

1. Maintain set of (nonce, timestamp) pairs
2. Reject packets with previously seen nonce
3. Expire entries older than tolerance window
4. Storage requirement: O(connections × tolerance / bucket_duration)

### 11.5 Silent Rejection

Servers MUST NOT send responses to invalid connection attempts:

- Invalid address: DROP (no response)
- Unknown or mismatched version: DROP (no response)
- Invalid timestamp: DROP (no response)
- Replayed nonce: DROP (no response)
- Failed handshake: close connection silently

This prevents attackers from distinguishing rejection reasons.

**Scope of silence**: For an address *not* in the valid set the firewall drops
the SYN, so no TCP handshake occurs and the endpoint is indistinguishable from
an unused address. For an address *in* the valid set, the kernel completes the
TCP handshake before the application processes the FirstPacket — so TCP-layer
liveness of a currently-valid tuple is observable to anyone who reaches it.
This is acceptable: reaching a valid tuple already requires knowledge of the
secret. Silent rejection therefore guarantees indistinguishability for invalid
tuples and reason-indistinguishability (never a distinguishing response) for
application-layer failures on valid tuples.

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

### 11.8 Prefix Size and Search Space

Address generation (Section 6.3) fills the bits below the advertised prefix length P with HMAC-derived output, so the protocol operates within a routed prefix of **any** length; P is not required to be 64. The prefix length sets the size of the search space an unauthorized party faces and nothing else — correctness, authentication, and confidentiality are all independent of P.

**Search target.** Because a conforming responder silently drops all traffic except its currently valid tuples (Section 11.5), an unauthorized party receives no distinguishing response until it addresses a packet to the *exact* live (address, port) tuple. The effective search target is therefore the whole tuple, not the address alone:

```
tuple entropy (bits) = (128 - P) address bits + log2(PORT_RANGE) port bits
                     ≈ (128 - P) + 16
```

**Rotation bound.** Every valid tuple is replaced each BUCKET_DURATION (Section 6.1). Resistance to enumeration is therefore governed not by the absolute space size but by the space size *relative to the probe rate an attacker can sustain within one bucket*: to locate a live tuple the attacker must sweep the space in less than BUCKET_DURATION seconds, after which the target has moved and any partial progress is void.

| Prefix P | Address bits | Tuple entropy | Tuple space | Sweep within one 300 s bucket |
| -------- | ------------ | ------------- | ----------- | ----------------------------- |
| /64  | 64 | ~80 | ~1.2×10^24 | infeasible                         |
| /80  | 48 | ~64 | ~1.8×10^19 | infeasible                         |
| /96  | 32 | ~48 | ~2.8×10^14 | infeasible (~10^12 packets/s)      |
| /112 | 16 | ~32 | ~4.3×10^9  | ~1.4×10^7 packets/s — high-rate but feasible |
| /120 |  8 | ~24 | ~1.7×10^7  | ~5.6×10^4 packets/s — trivial      |
| /128 |  0 | ~16 | ~6.5×10^4  | instant (address fixed, only the port rotates) |

At P = 128 the address is fixed and only the port rotates; the scheme retains no address-level concealment and degrades to a single well-known address with a moving port.

**Graceful degradation.** A longer prefix (fewer host bits) weakens only the *concealment* and *unlinkability* of the address stream (the "Address unpredictability" property of Section 11.2) — the ability to keep the service unenumerable and successive connections uncorrelated. It does **not** weaken confidentiality or authentication: an attacker who enumerates a small prefix and reaches a live tuple still faces the Noise IKpsk2 handshake and gains nothing without the peer static key and the handshake password (Section 8.2). The address scheme is a concealment layer over an independently sound cryptographic layer, so it fails soft rather than catastrophically.

**Guidance.** Responders SHOULD advertise the routed prefix that leaves the most host bits available to them (the shortest prefix length / largest address block that actually routes to the host). A prefix length of /96 or shorter (at least ~32 host bits) keeps single-bucket enumeration infeasible even for a well-resourced attacker; /64 — a typical delegated segment — provides a wide margin. Longer prefixes remain correct and fully functional but provide progressively weaker concealment, and SHOULD be limited to deployments where enumeration of the responder's prefix is outside the threat model, or where the reduced address space is compensated by additional network-layer filtering and rate limiting (Section 11.6).

---

## 12. Implementation Requirements

### 12.1 Mandatory Features

Implementations MUST support:

- X25519 key generation and agreement
- HKDF-SHA256 key derivation
- HMAC-SHA256 address generation
- Noise_IKpsk2_25519_ChaChaPoly_SHA256 handshake
- Noise prologue bound to the First Packet header (Section 4.4)
- Handshake payload length validation (Section 4.4)
- Length-prefixed message framing (Section 7.1)
- Timestamp validation with configurable tolerance
- Nonce tracking and replay rejection
- Address window computation (current ±1 bucket)
- Binding computed addresses within a routed prefix without per-address interface provisioning (Section 6.3)
- Verifying the handshake-authenticated peer static key against the relationship (Section 8.2)

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

### 12.4 Operational Requirements

- **Tuple collisions**: Distinct (relationship, service, bucket) streams can,
  with cryptographically negligible probability, compute the same
  (address, port). An implementation MUST NOT silently double-book a tuple; it
  SHOULD detect the collision and log it rather than bind two services behind
  one listener.
- **Graceful shutdown**: On orderly shutdown an implementation SHOULD remove
  its firewall state (valid-set entries). Crash safety does not depend on this:
  each valid-set entry carries a timeout equal to its remaining validity, so a
  daemon that dies without cleanup leaves entries the kernel expires on its own
  (Section 11.6). A `SIGTERM`-triggered cleanup is RECOMMENDED.
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

All address vectors use:

```
session_key = 0xcf9dfe21bf261783 7c0c50d8bb14555e
              45e3d2023cedea4c e2ce0bfb48dde05e   # From Section 13.3
responder_pubkey = bob_public                     # From Section 13.2
service_id = 0x0f0e0d0c0b0a0908 0706050403020100
```

**Vector A — /64 prefix**:

```
Input:
    responder_prefix = 2001:db8:1234:5678::/64    # P = 64
    timestamp = 1706295600  # 2024-01-26 19:00:00 UTC (exact bucket boundary)
    T = floor(1706295600 / 300) = 5687652  # 0x000000000056c964

Intermediate:
    input = 0x000000000056c964 || "montauk-v1-address" || bob_public || service_id
    raw = 0xc2ffd88025566ce5 9045c6c4d54a135a
          747d431efdb1f3ef fcdb66edf3fc9958

Output:
    ipv6_address = 2001:db8:1234:5678:9045:c6c4:d54a:135a
    port = 30845   # port_raw = 0x747d = 29821; 1024 + (29821 mod 64511)
```

**Vector B — /80 prefix (exercises non-/64 masking)**:

```
Input:
    responder_prefix = 2001:db8:1234:5678:9abc::/80   # P = 80
    T = 5687652   # Same inputs as Vector A otherwise

Intermediate:
    raw = (identical to Vector A: the prefix is not an HMAC input)

Output:
    ipv6_address = 2001:db8:1234:5678:9abc:c6c4:d54a:135a
    port = 30845   # Identical to Vector A
```

**Vector C — port modulo (port_raw ≥ PORT_RANGE)**:

```
Input:
    responder_prefix = 2001:db8:1234:5678::/64
    timestamp = 1706321400  # 2024-01-27 02:10:00 UTC
    T = 5687738  # 0x000000000056c9ba

Intermediate:
    raw = 0xb343b4d7e9c46f4d a213fa43dec4679f
          fd007be8fe387882 9b3115c59d1ae66a

Output:
    ipv6_address = 2001:db8:1234:5678:a213:fa43:dec4:679f
    port = 1281   # port_raw = 0xfd00 = 64768 ≥ 64511; 1024 + (64768 mod 64511)
```

### 13.5 First Packet

Uses noise_message_1 from the direct handshake transcript (Section 13.6):

```
Input:
    version = 0x01
    timestamp = 1706295600
    nonce = 0x000102030405060708090a0b0c0d0e0f
    payload = noise_message_1   # 96 bytes, Section 13.6

Output:
    frame_body = 0x01 || 0x0000000065b40130 || 0x000102030405060708090a0b0c0d0e0f || noise_message_1
    noise_prologue = frame_body[0:25]   # version || timestamp || nonce (Section 4.4)
    wire_format = 0x0079 || frame_body  # 121-byte body, 123 bytes on the wire
```

### 13.6 Handshake Transcript (Direct)

Full Noise_IKpsk2_25519_ChaChaPoly_SHA256 handshake with fixed ephemeral keys. Alice initiates; Bob responds. The static keys are the pair from Section 13.2; the initiator ephemeral is the key from Section 13.1. Per Section 4.4, both handshake payloads are empty (the service is selected by the address, Vector A of Section 13.4).

```
Input:
    init_static = alice_private                       # Section 13.2
    resp_static = 0x5dab087e624a8a4b 79e17f8b83800ee6
                  6f3bb1292618b6fd 1c2f8b27ff88e0eb   # bob_private
    init_ephemeral = 0x0001020304050607 08090a0b0c0d0e0f
                     1011121314151617 18191a1b1c1d1e1f   # Section 13.1 key
    resp_ephemeral = 0x4041424344454647 48494a4b4c4d4e4f
                     5051525354555657 58595a5b5c5d5e5f
    resp_ephemeral_pub = 0x79a631eede1bf9c9 8f12032cdeadd0e7
                         a079398fc786b88c c846ec89af85a51a
    psk (handshake_password) = 0x6061626364656667 68696a6b6c6d6e6f
                               7071727374757677 78797a7b7c7d7e7f
    prologue = 0x01 || 0x0000000065b40130 || 0x000102030405060708090a0b0c0d0e0f
    msg1_payload = empty
    msg2_payload = empty

Output:
    noise_message_1 (96 bytes) =
        0x8f40c5adb68f2562 4ae5b214ea767a6e c94d829d3d7b5e1a d1ba6f3e2138285f
          b7983d2f78e86e68 627ad14f8e48a8dc 563c3b7bdc8ed982 0f59e762fdbb7c40
          e5ce5d480fd47788 73a7192808890d9e 1b578ab8fbd911ff 05935702900a9e14

    noise_message_2 (48 bytes) =
        0x79a631eede1bf9c9 8f12032cdeadd0e7 a079398fc786b88c c846ec89af85a51a
          f689e44f383a6d2c f4fefbb9f157e382

    handshake_hash =
        0xa4d854c2aebc7e23 f8248cbcc402d5a7 1f8537718673ee9e 26b05abe6965cdde

    transport_1 (initiator → responder, plaintext "ping", 20 bytes) =
        0x892a5643ce98792b c9f31eda2a98ebb1 13c206e3

    transport_2 (responder → initiator, plaintext "pong", 20 bytes) =
        0xe2bf3db33c5f6e1b ac08525760048663 2a256ba2
```

On the wire, noise_message_2 is framed as 0x0030 || noise_message_2 and each transport message as 0x0014 || transport (Section 7.1).

### 13.7 Handshake Transcript (Brokered)

Identical inputs to Section 13.6 except the First Packet nonce (and therefore the prologue), and the message 1 payload, which carries the service_id from Section 13.4 (Sections 4.4 and 7.4):

```
Input:
    nonce = 0x101112131415161718191a1b1c1d1e1f
    prologue = 0x01 || 0x0000000065b40130 || 0x101112131415161718191a1b1c1d1e1f
    msg1_payload = service_id = 0x0f0e0d0c0b0a0908 0706050403020100
    msg2_payload = empty

Output:
    noise_message_1 (112 bytes) =
        0x8f40c5adb68f2562 4ae5b214ea767a6e c94d829d3d7b5e1a d1ba6f3e2138285f
          b7983d2f78e86e68 627ad14f8e48a8dc 563c3b7bdc8ed982 0f59e762fdbb7c40
          c920351fb82ad24d a835fad0ec39f92f a38477b0ebadb6c7 98dfc16e5a115540
          548ad38e5570b509 e29877dbe4513124

    noise_message_2 (48 bytes) =
        0x79a631eede1bf9c9 8f12032cdeadd0e7 a079398fc786b88c c846ec89af85a51a
          5e04cf6f6ad1a2a3 44bd386c030ab9ec

    handshake_hash =
        0x9bf3604eac6ba2dc 2b090db8eeb80efa 39b6b0d6e5994692 452117d09a39d8d8
```

The First Packet frame body is 137 bytes (wire_format = 0x0089 || frame_body).

_Note: All test vectors are complete. They were generated with a reference implementation whose X25519 is validated against RFC 7748 Section 6.1 and whose Noise stack reproduces the official cacophony test vector for Noise_IKpsk2_25519_ChaChaPoly_SHA256 byte-for-byte, including transport messages and handshake hash._

_The test vectors in this section are dedicated to the public domain under CC0 1.0: use them in any implementation or test suite, no attribution required._

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

BrokerAccept:
+--------+------------------+
|  Type  |     Match ID     |
| 1 byte |    16 bytes      |
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

### Version 0.4.0-draft (July 2026)

Folds in findings from building and validating the reference implementation
(M0–M5, including real cross-host and brokered runs). All changes are
clarifications and added requirements; no wire formats or test vectors change.

- §8.2: the responder MUST verify the handshake-authenticated initiator static key equals the relationship's `peer_pubkey` and close silently on mismatch (address + PSK selection alone does not bind a connection to an identity)
- §8.2: if a service's `internal_target` is down, the responder MUST still complete the handshake before closing, so liveness is revealed only to an authenticated peer; and connection close is a per-direction TCP FIN carried through the channel (half-close permitted)
- §11.3: stated that timestamp validity and address-window validity are independent checks with different tolerances, and both must pass
- §11.5: clarified the scope of silent rejection — invalid tuples are fully indistinguishable, but a currently-valid tuple completes the TCP handshake at the kernel before the application responds (acceptable, since reaching it requires the secret)
- §6.3, §12.1: binding a computed address requires a non-local-bind facility (`IPV6_FREEBIND`) in addition to the routing prefix; made this a mandatory capability
- §12.4 (new): implementations MUST NOT silently double-book a colliding tuple, and SHOULD remove firewall state on graceful shutdown (crash safety already rests on valid-set timeouts)
- §9.3: clarified that broker authorization MUST use the identities parties authenticated with in their Noise handshake to the broker, not values asserted in messages
- §6.4: corrected the tolerance claim — the effective clock-skew tolerance is the intersection of the address window and the ±30s timestamp window (≈±30s), not ±5 minutes (from independent review)
- §8.2, §9.5: noted that the TCP FIN carrying end-of-stream is not authenticated, so an on-path attacker or the broker can truncate the stream undetectably (from independent review)
- §11.8 (new): documented the prefix-size / search-space tradeoff — the protocol works within a routed prefix of any length P, with tuple entropy ≈ (128−P) + 16 bits and enumeration resistance governed by space-per-bucket vs. attacker probe rate; a smaller prefix degrades concealment/unlinkability only, not confidentiality or authentication (§5.4, §6.3 cross-referenced)

### Version 0.3.0-draft (July 2026)

- Defined the Noise prologue as the 25-byte First Packet header, binding the timestamp and nonce into the handshake (replayed or re-stamped packets now fail AEAD decryption and are dropped silently, including through brokers)
- Address derivation now includes the service_id: each service has its own address stream, the connected tuple selects the service, and per-service revocation is enforced at the network layer; removed the ServiceRequest message
- Brokered connections carry the service_id as the Noise message 1 payload; added BROKER_SERVICE_ID for broker rendezvous connections
- Handshake payload lengths are strictly validated (zero-length except brokered message 1)
- Unknown version bytes are silently dropped; versions are pinned at relationship establishment, never negotiated in-band
- Reworked the broker protocol as a control/data split: control connections stay registered and receive MATCH_OFFER with a single-use match_id; bridges run on dedicated data connections claimed via the new BrokerAccept message
- Added broker keepalives (zero-length Noise transport messages), default timeouts, and per-client limits
- Rewrote the broker state machine (control connections never leave REGISTERED; matches are independent objects)
- Regenerated the address generation vectors for the new derivation; added vectors for non-/64 prefix masking and the port modulo path
- Added complete handshake transcript vectors for direct and brokered connections (Sections 13.6–13.7), validated against the official Noise cacophony vectors, and completed the First Packet vector

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
