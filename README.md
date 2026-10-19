# 🛡️ ServerWatcher (Vortex Shield v2) — TCP Reverse Proxy & DPI Firewall for CrossFire SA (v1911)

**ServerWatcher** is a high-performance, multi-threaded C++ TCP Reverse Proxy and Deep Packet Inspection (DPI) firewall engineered specifically to protect legacy **CrossFire SA (v1911)** server binaries (`LoginServer` & `GameServer`). 

Beyond acting as a Layer-4/Layer-7 DDoS mitigation gateway, this solution was primarily built to neutralize a critical, unpatched **Heap/Stack Buffer Overflow vulnerability** present in the native packet reassembly engine of the leaked v1911 server binaries.

---

## 🚨 The Vulnerability: Fragmented Packet Buffer Overflow (v1911)

In the CrossFire v1911 protocol, client-server communication relies on the `T_PACKET` structure, which allocates a fixed maximum buffer of **17,408 bytes** (`8-byte header` + `17,399-byte payload` + alignment):

~~~cpp
struct ProtoData { byte aDummy[17399]; };

#pragma pack(push, 1)
struct T_PACKET {
    uint8_t tStartByte;               // Magic Byte (Must be 241 / 0xF1)
    uint16_t wSize;                   // Packet Size
    uint8_t firstClass;               // Category ID
    uint8_t secondClass;              // Sub-category ID
    uint8_t thirdClass;               // Command ID
    uint8_t extensionPacketCount;     // Total expected fragments
    uint8_t extensionPacketCurCount;  // Current fragment index (1-based)
    ProtoData userData;               // Fixed 17,399-byte payload buffer
};
#pragma pack(pop)
~~~

### How the Exploit Works:
When a packet exceeds the standard MTU or buffer chunk, the protocol uses `extensionPacketCount` and `extensionPacketCurCount` to split data across multiple transmissions. However, the native v1911 server binary fails to validate the **cumulative size** of incoming extension chunks during reassembly.

By spoofing `extensionPacketCount` and continuously streaming chunks where the cumulative byte count exceeds **17,408 bytes**, an attacker triggers a fatal **Buffer Overflow**, corrupting adjacent server memory and immediately crashing the `LoginServer` or `GameServer` process.

### How ServerWatcher Fixes It:
`ServerWatcher` sits transparently in front of the server binaries as a Reverse Proxy. It inspects the `T_PACKET` header of every incoming stream in real-time:
1. Tracks stateful packet reassembly per client session (`m_totalExtensionSize`).
2. Resets the counter when `extensionPacketCurCount == 1` and accumulates sizes across subsequent extension frames.
3. **Instant Mitigation:** If the cumulative size of an extended packet sequence exceeds `17,408 bytes`, the proxy immediately terminates the socket before the malicious payload reaches the vulnerable server binary, logs the offense, and permanently blacklists the attacker's IP.

---

## 🏗️ Solution Architecture

The Visual Studio solution (`ServerWatcher.sln`) consists of two dedicated proxy shields:
1. **`LoginServerWatcher`**: Protects the Authentication/Login Server (Default forwarding: `28888` ➡️ `18889`).
2. **`GameServerWatcher`**: Protects the core Game Server with additional `SO_KEEPALIVE` socket stability (Default forwarding: `22367` ➡️ `12367`).

~~~text
[ Game Client ] 
       │
       ▼ (Public Port: e.g., 28888 / 22367)
┌──────────────────────────────────────────────────────────┐
│              ServerWatcher (Vortex Shield)               │
│  ├─ 1. IP Blacklist & Connection Rate Limiter            │
│  ├─ 2. MaxMind GeoIP Country Filter (GeoGuard)           │
│  ├─ 3. Pre-Auth Magic Byte Check (StartByte == 241)      │
│  ├─ 4. PPS / BPS Flood & DDoS Protection                 │
│  └─ 5. Stateful Extension Packet Overflow Guard (17408B) │
└──────────────────────────────────────────────────────────┘
       │
       ▼ (Internal Local Port: e.g., 18889 / 12367)
[ Vulnerable CF v1911 Server Binary ]
~~~

---

## ✨ Key Security & Engineering Features

* **Stateful DPI (Deep Packet Inspection):**
  * **Magic Byte Enforcement:** Drops and bans any connection whose initial handshake packet is smaller than 8 bytes or does not start with `tStartByte == 241` (`0xF1`).
  * **Extension Overflow Guard:** Strictly enforces the `17,408-byte` ceiling across fragmented packets.
* **Multi-Layered Flood & DDoS Mitigation:**
  * **Bandwidth & Packet Throttling:** Real-time per-client tracking of **PPS** (Packets Per Second) and **BPS** (Bytes Per Second). Clients exceeding `1.5x MAX_PPS` are automatically banned.
  * **Connection Rate Limiting:** Enforces minimum intervals between new connections from the same IP (`CONN_RATE_MS`), per-IP concurrent connection caps (`MAX_CONNS_PER_IP`), and global connection ceilings (`GLOBAL_MAX_CONNECTIONS`).
  * **Slowloris / Pre-Auth Protection:** Applies `SO_RCVTIMEO` (`PRE_AUTH_TIMEOUT_MS`) prior to initial packet validation to prevent dead-connection exhaustion.
* **GeoIP Country Filtering (`GeoGuard`):**
  * Integrated with **MaxMindDB (`libmaxminddb`)** using memory-mapped files (`MMDB_MODE_MMAP`) for zero-overhead country lookup via `GeoLite2-Country.mmdb`.
* **Live Hot-Reloading Configuration:**
  * A dedicated background thread (`ConfigWatcherThread`) monitors `config.ini` every 3 seconds, dynamically updating rate limits, debug modes, admin whitelists, and blacklist states in real-time without restarting the server or disconnecting active players.
* **Low-Latency Socket & Threading Design:**
  * Built with native Win32 Critical Sections (`FastMutex` & RAII `FastGuard`) and atomic operations (`InterlockedIncrement`/`Decrement`).
  * Configured with `TCP_NODELAY` (Nagle's algorithm disabled) and `SO_LINGER` for minimal proxy latency and instant socket recycling.

---

## ⚙️ Configuration (`config.ini`)

Create a `config.ini` file in the root directory alongside the compiled executables:

~~~ini
[VORTEX_PROTECTION_BY_SHE3A]
IP=127.0.0.1
LPORT=28888
EXLPORT=18889
GPORT=22367
EXGPORT=12367

[LOGIN_CONFIG]
GLOBAL_DEBUG_MODE=1
MAX_PPS=1500
MAX_BPS=5242880
GLOBAL_MAX_CONNECTIONS=700
MAX_CONNS_PER_IP=30
CONN_RATE_MS=250
PRE_AUTH_TIMEOUT_MS=35000
ENABLE_BLACKLIST=1
ADMIN_IP_1=127.0.0.1
ADMIN_IP_2=127.0.0.1

[GAMESRV_CONFIG]
GLOBAL_DEBUG_MODE=1
MAX_PPS=1500
MAX_BPS=5242880
GLOBAL_MAX_CONNECTIONS=700
MAX_CONNS_PER_IP=30
CONN_RATE_MS=250
PRE_AUTH_TIMEOUT_MS=35000
ENABLE_BLACKLIST=1
ADMIN_IP_1=127.0.0.1
ADMIN_IP_2=127.0.0.1
~~~

*Note: Place `GeoLite2-Country.mmdb` and `blacklist.txt` in the same directory as the executables.*

---

## 🛠️ Tech Stack

* **Language:** C++ (Win32 API)
* **Networking:** Winsock2 (`ws2_32.lib`), Stateful TCP Proxy Sockets
* **GeoIP Engine:** MaxMindDB (`libmaxminddb`)
* **Concurrency:** Multi-threaded Client Handlers, Win32 Critical Sections (RAII)

---

## ⚠️ License & Usage Terms

This project was developed and open-sourced by **Ali She3a (Vortex)** to help private server developers secure legacy CrossFire infrastructure.

1. **Free for Personal & Educational Use:** You are free to study, modify, and deploy this proxy on your servers.
2. **Strictly NO Commercial Sale:** Selling this source code or compiled binaries derived from it is **strictly prohibited**.
3. **Support & Contact:** For technical discussions or integration help, reach out on Discord: `ashe3a`.
