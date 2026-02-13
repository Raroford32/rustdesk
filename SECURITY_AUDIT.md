# RustDesk Security Code Review - Comprehensive Audit Report

## Executive Summary

This report documents a thorough security code review of the RustDesk open-source remote desktop codebase. The review examined authentication, IPC mechanisms, network protocol handling, file transfer security, cryptographic implementations, privilege escalation vectors, and platform-specific code. Several vulnerabilities of varying severity were identified.

---

## FINDING 1: IPC Socket World-Accessible — Local Privilege Escalation via Credential Theft

**Severity:** CRITICAL
**Files:** `src/ipc.rs:428-444` (listener), `src/ipc.rs:518-800` (handler)
**Impact:** Any local user can read connection passwords, modify configuration, and gain full remote access
**Type:** CWE-732 (Incorrect Permission Assignment for Critical Resource)

### Description

The IPC socket used for inter-process communication between the RustDesk UI and service is created with overly permissive access controls:

```rust
// src/ipc.rs:433-434
match SecurityAttributes::allow_everyone_create() {
    Ok(attr) => endpoint.set_security_attributes(attr),
```

On Unix systems, the socket permissions are explicitly set to world-readable/writable:

```rust
// src/ipc.rs:442-443
use std::os::unix::fs::PermissionsExt;
std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0777)).ok();
```

### Exploitable IPC Handler Actions

The IPC `handle()` function at `src/ipc.rs:518` processes messages from any connected client. Through this world-accessible socket, a low-privilege local user can:

1. **Read the permanent password** (`src/ipc.rs:635`):
   ```rust
   } else if name == "permanent-password" {
       value = Some(Config::get_permanent_password());
   ```

2. **Read the temporary password** (`src/ipc.rs:633`):
   ```rust
   } else if name == "temporary-password" {
       value = Some(password::temporary_password());
   ```

3. **Read the salt** (`src/ipc.rs:637`):
   ```rust
   } else if name == "salt" {
       value = Some(Config::get_salt());
   ```

4. **Read key pairs** (`src/ipc.rs:582-587`):
   ```rust
   Data::ConfirmedKey(None) => {
       let out = if Config::get_key_confirmed() {
           Some(Config::get_key_pair())
       ...
   ```

5. **Set a new permanent password** (`src/ipc.rs:677`):
   ```rust
   } else if name == "permanent-password" {
       Config::set_permanent_password(&value);
   ```

6. **Modify configuration options** (`src/ipc.rs:696-703`), including disabling security features

7. **Set the unlock PIN** (`src/ipc.rs:683`):
   ```rust
   } else if name == "unlock-pin" {
       Config::set_unlock_pin(&value);
   ```

8. **Trigger service termination** (`src/ipc.rs:538-574`, `Data::Close`)

9. **Remove trusted devices** (`src/ipc.rs:374`, `Data::RemoveTrustedDevices`)

### Attack Scenario

1. Attacker has low-privilege shell access on the target machine (e.g., shared hosting, compromised web app)
2. Attacker connects to the IPC socket at the known path
3. Attacker sends `Data::Config(("permanent-password", None))` to read the password
4. Attacker remotely connects to the RustDesk service using the stolen password
5. Full remote desktop access is achieved, including keyboard/mouse, file transfer, and terminal

### Recommendation

- Set IPC socket permissions to `0o0600` (owner-only) on Unix
- Use `SecurityAttributes::allow_everyone_connect()` → restrict to the service user
- Implement authentication on the IPC channel (e.g., shared secret or peer credential checking via `SO_PEERCRED`)

---

## FINDING 2: Custom Server Configuration Signature Bypass

**Severity:** HIGH
**File:** `src/custom_server.rs:21-37`
**Impact:** Redirect application to a malicious rendezvous/relay server without signature verification
**Type:** CWE-347 (Improper Verification of Cryptographic Signature)

### Description

The `get_custom_server_from_config_string()` function attempts to parse custom server configuration. It first tries to parse the base64-decoded data as JSON *before* checking the cryptographic signature:

```rust
fn get_custom_server_from_config_string(s: &str) -> ResultType<CustomServer> {
    let tmp: String = s.chars().rev().collect();
    // ... PK definition ...
    let data = URL_SAFE_NO_PAD.decode(tmp)?;
    // BUG: Returns unsigned data if it parses as valid JSON
    if let Ok(lic) = serde_json::from_slice::<CustomServer>(&data) {
        return Ok(lic);  // <-- NO SIGNATURE VERIFICATION
    }
    // Signature check only happens if JSON parse fails
    if let Ok(data) = sign::verify(&data, &pk) {
        Ok(serde_json::from_slice::<CustomServer>(&data)?)
    } else {
        bail!("sign:verify failed");
    }
}
```

Additionally, `get_custom_server_from_string()` at `src/custom_server.rs:59` also accepts `host=...` parameters from the executable filename entirely without any signing:

```rust
if s.to_lowercase().contains("host=") {
    // Parse host, key, api, relay directly — no signature check
```

### Attack Scenario

Combined with Finding 1 (IPC world-accessible):
1. Attacker modifies the rendezvous server configuration via IPC `Data::Options`
2. RustDesk connects to attacker-controlled rendezvous server
3. Attacker performs MITM on all future remote connections

Or via executable renaming:
1. Attacker renames the RustDesk binary to include `host=evil.com`
2. Application connects to attacker's server

### Recommendation

- Always verify the signature BEFORE accepting the parsed configuration
- Move the JSON parsing after the `sign::verify` check

---

## FINDING 3: 2FA TOTP Secret Encrypted with Hardcoded Key

**Severity:** HIGH
**File:** `src/auth_2fa.rs:55-66`
**Impact:** Anyone with config file access can decrypt 2FA secret and bypass TOTP authentication
**Type:** CWE-798 (Use of Hard-coded Credentials)

### Description

The TOTP secret for 2FA is encrypted using a hardcoded key `"00"`:

```rust
// Encryption (src/auth_2fa.rs:55)
let secret = encrypt_vec_or_original(self.secret.as_slice(), "00", 1024);

// Decryption (src/auth_2fa.rs:66)
let (secret, success, _) = decrypt_vec_or_original(&totp_info.secret, "00");
```

Since the encryption key is a constant embedded in the binary (`"00"`), anyone who can read the configuration file can:
1. Extract the encrypted 2FA secret
2. Decrypt it using the known key
3. Generate valid TOTP codes
4. Bypass 2FA completely

### Attack Amplification

Combined with Finding 1, any local user can:
1. Read the config via IPC to obtain the encrypted 2FA secret
2. Decrypt with the known key `"00"`
3. Generate valid 2FA codes

### Recommendation

- Derive the encryption key from machine-specific entropy (e.g., machine ID + service key)
- Use OS-level credential storage (Windows Credential Manager, macOS Keychain, Linux Secret Service)

---

## FINDING 4: Post-Authentication SSRF via Port Forwarding

**Severity:** MEDIUM
**File:** `src/server/connection.rs:2175-2207`
**Impact:** Authenticated remote peer can scan internal networks and access internal services
**Type:** CWE-918 (Server-Side Request Forgery)

### Description

When a remote peer requests port forwarding, the server connects to any host:port combination specified by the peer:

```rust
Some(login_request::Union::PortForward(mut pf)) => {
    if pf.host.is_empty() {
        pf.host = "localhost".to_owned();
    }
    let mut addr = format!("{}:{}", pf.host, pf.port);
    self.port_forward_address = addr.clone();
    match timeout(3000, TcpStream::connect(&addr)).await {
        Ok(Ok(sock)) => {
            self.port_forward_socket = Some(Framed::new(sock, BytesCodec::new()));
        }
```

No validation is performed on the host/port. An authenticated attacker can:
- Scan internal network ranges (10.x, 172.16.x, 192.168.x)
- Access cloud metadata endpoints (169.254.169.254)
- Connect to internal databases, caches, or APIs
- Pivot through the compromised host into the internal network

### Recommendation

- Add an allowlist/blocklist for port forwarding destinations
- Block RFC 1918 private addresses, link-local, and loopback by default
- Block cloud metadata IPs (169.254.169.254)
- Allow configuration of permitted forwarding targets

---

## FINDING 5: Insecure TLS Fallback Configurable via IPC

**Severity:** MEDIUM
**File:** `src/ipc.rs:480-483`, `src/hbbs_http/http_client.rs:23-24`
**Impact:** Local attacker can disable TLS certificate validation, enabling MITM
**Type:** CWE-295 (Improper Certificate Validation)

### Description

The `allow-insecure-tls-fallback` option can be configured via IPC:

```rust
// src/ipc.rs:480-483
allow_insecure_tls_fallback: Config::get_option(
    config::keys::OPTION_ALLOW_INSECURE_TLS_FALLBACK,
),
```

When enabled, the HTTP client accepts invalid TLS certificates:

```rust
// src/hbbs_http/http_client.rs:23-24
if $danger_accept_invalid_cert {
    builder = builder.danger_accept_invalid_certs(true);
}
```

Combined with the world-accessible IPC socket (Finding 1), a local attacker can:
1. Enable insecure TLS fallback via IPC
2. Perform DNS poisoning or ARP spoofing on the local network
3. MITM all HTTPS communication between RustDesk and its API servers

### Recommendation

- Restrict IPC access (see Finding 1 recommendation)
- Require user confirmation via the GUI before enabling insecure TLS

---

## FINDING 6: RDP Credentials Exposed in Environment Variables

**Severity:** MEDIUM
**File:** `src/port_forward.rs:23-37`
**Impact:** RDP credentials readable by other processes of the same user
**Type:** CWE-214 (Invocation of Process Using Visible Sensitive Information)

### Description

RDP credentials are read from environment variables and passed to `cmdkey`:

```rust
let username = std::env::var("rdp_username").unwrap_or_default();
let password = std::env::var("rdp_password").unwrap_or_default();
// ...
args.push(format!("/pass:{}", password));
println!("{:?}", args);  // Password printed to stdout!
std::process::Command::new("cmdkey").args(&args).output().ok();
```

Issues:
1. Environment variables are readable via `/proc/[pid]/environ` on Linux
2. The password is **printed to stdout** via `println!`
3. The password is passed as a command-line argument to `cmdkey`, visible in process listings
4. `cmdkey` stores credentials in Windows Credential Manager for `localhost`, which persists

### Recommendation

- Don't use environment variables for credentials
- Remove the `println!` that logs credentials
- Use Windows Credential Manager API directly instead of `cmdkey` command-line tool
- Clear credentials after use

---

## FINDING 7: Plugin Framework — Arbitrary Code Execution via Dynamic Library Loading

**Severity:** HIGH (when plugin framework feature is enabled)
**File:** `src/plugin/plugins.rs:179-185`, `src/plugin/manager.rs:164-188`
**Impact:** Arbitrary native code execution via malicious plugins
**Type:** CWE-94 (Improper Control of Generation of Code)

### Description

The plugin system loads shared libraries and calls FFI functions:

```rust
// src/plugin/plugins.rs:179-185
fn new(path: &str) -> ResultType<Self> {
    let lib = match Library::open(path) {
        Ok(lib) => lib,
        Err(e) => bail!("Failed to load library {}, {}", path, e),
    };
```

Plugin installation requires elevation (`src/plugin/manager.rs:164-188`), which means plugins run with elevated privileges. The plugin install flow:
1. Downloads plugin from a URL
2. Elevates privileges via `crate::platform::elevate()`
3. Loads the shared library
4. Calls FFI functions with full process permissions

While the plugin source list is currently empty (`vec![]` at `src/plugin/manager.rs:65`), the infrastructure is fully implemented. If enabled or if a local attacker can place a malicious `.so`/`.dll` in the plugin directory, arbitrary code execution occurs with elevated privileges.

### Recommendation

- Implement plugin signature verification
- Sandbox plugin execution
- Validate plugin source URLs against a pinned list
- Add integrity checks for downloaded plugin binaries

---

## FINDING 8: Session Hijacking via IPC-Triggered Disconnect + Recent Session Reuse

**Severity:** MEDIUM
**File:** `src/server/connection.rs:1940-1961`
**Impact:** Local attacker can hijack active remote sessions
**Type:** CWE-384 (Session Fixation)

### Description

The "recent session" mechanism allows reconnection within 30 seconds without re-authentication:

```rust
fn is_recent_session(&mut self, tfa: bool) -> bool {
    SESSIONS.lock().unwrap()
        .retain(|_, s| s.last_recv_time.lock().unwrap().elapsed() < SESSION_TIMEOUT);
    // ... if session exists and password matches, return true
}
```

`SESSION_TIMEOUT` is 30 seconds (`src/server/connection.rs:347`).

Combined with the world-accessible IPC:
1. Attacker monitors for active sessions
2. Sends `Data::Close` via IPC to disconnect the legitimate user
3. Reconnects within 30 seconds using the cached session token
4. Gains the permissions of the original session

### Recommendation

- Invalidate session tokens on abnormal disconnects
- Bind sessions to the source IP/connection
- Require re-authentication after unexpected disconnects

---

## FINDING 9: Login Rate Limiting Reset via Service Restart

**Severity:** LOW-MEDIUM
**File:** `src/server/connection.rs:3334-3462`
**Impact:** Brute-force rate limiting can be bypassed by restarting the service
**Type:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

### Description

Login failure tracking is stored only in memory:

```rust
static ref LOGIN_FAILURES: [Arc::<Mutex<HashMap<String, (i32, i32, i32)>>>; 2] = Default::default();
```

Rate limits:
- 6 attempts per minute per IP
- 30 total attempts per IP

A service restart (achievable via IPC `Data::Close`) clears all lockout state. An attacker can:
1. Attempt 6 passwords
2. Restart the service via IPC
3. Attempt 6 more passwords
4. Repeat indefinitely

This reduces brute-force protection to only the time cost of service restarts.

### Recommendation

- Persist login failure counts to disk
- Implement exponential backoff that survives restarts
- Use a separate, non-IPC-resettable lockout mechanism

---

## FINDING 10: LAN Discovery Information Disclosure

**Severity:** LOW
**File:** `src/lan.rs:27-73`
**Impact:** Network reconnaissance — device ID, hostname, username, MAC address, platform leaked
**Type:** CWE-200 (Exposure of Sensitive Information)

### Description

LAN discovery responds to broadcast pings with:
- Device ID
- Hostname
- Active username
- MAC address
- Platform/OS type

```rust
let peer = PeerDiscovery {
    cmd: "pong".to_owned(),
    mac: get_mac(&self_addr),
    id,
    hostname,
    username: crate::platform::get_active_username(),
    platform: whoami::platform().to_string(),
    ..Default::default()
};
```

Any device on the local network can enumerate all RustDesk instances and their users.

---

## FINDING 11: Windows `update_install_option` Potential Command Injection

**Severity:** MEDIUM
**File:** `src/platform/windows.rs:1804-1815`
**Impact:** Potential command injection in elevated context
**Type:** CWE-78 (Improper Neutralization of Special Elements in OS Commands)

### Description

```rust
pub fn update_install_option(k: &str, v: &str) -> ResultType<()> {
    let cmds = format!(
        "chcp 65001 && reg add HKEY_CLASSES_ROOT\\.{ext} /f /v {k} /t REG_SZ /d \"{v}\""
    );
    run_cmds(cmds, false, "update_install_option")?;
```

The `k` and `v` parameters are inserted into a shell command string without sanitization. The `run_cmds` function writes this to a `.bat` file and executes it with `runas::Command` (elevated). If `v` contains `" && malicious_command && "`, it would execute arbitrary commands with elevation.

The `v` parameter comes from options that can potentially be influenced via the IPC socket.

### Recommendation

- Use the Windows Registry API directly instead of shell commands
- If shell commands are necessary, sanitize all parameters
- Escape or reject special characters in option values

---

## FINDING 12: Portable Service TOCTOU Race in Binary Extraction

**Severity:** LOW-MEDIUM
**File:** `libs/portable/src/main.rs:62-99`
**Impact:** Code execution via binary replacement during extraction
**Type:** CWE-367 (Time-of-check Time-of-use Race Condition)

### Description

The portable launcher:
1. Removes the target directory: `std::fs::remove_dir_all(&dir).ok()`
2. Extracts all files to the directory
3. Executes the extracted binary

The target directory (`%LOCALAPPDATA%\rustdesk` on Windows) is user-writable. Between steps 2 and 3, an attacker could replace the extracted binary with a malicious one.

### Recommendation

- Verify extracted file integrity before execution (hash check)
- Use exclusive file locks during extraction and execution
- Extract to a temporary directory and atomically move

---

## Summary Table

| # | Finding | Severity | Type | Auth Required |
|---|---------|----------|------|--------------|
| 1 | IPC Socket World-Accessible | CRITICAL | Local Priv Esc | No (local) |
| 2 | Custom Server Signature Bypass | HIGH | Config Tampering | No |
| 3 | 2FA Secret Hardcoded Key | HIGH | Auth Bypass | Config access |
| 4 | Port Forwarding SSRF | MEDIUM | SSRF | Yes (remote) |
| 5 | Insecure TLS via IPC | MEDIUM | MITM | No (local) |
| 6 | RDP Creds in Env/Stdout | MEDIUM | Info Disclosure | N/A |
| 7 | Plugin Arbitrary Code Exec | HIGH | RCE | Elevation |
| 8 | Session Hijacking via IPC | MEDIUM | Session Hijack | No (local) |
| 9 | Rate Limit Reset via Restart | LOW-MEDIUM | Brute Force | No (local) |
| 10 | LAN Discovery Info Leak | LOW | Info Disclosure | No (network) |
| 11 | Windows Registry Cmd Injection | MEDIUM | Command Injection | Local/IPC |
| 12 | Portable TOCTOU Race | LOW-MEDIUM | Race Condition | Local |

---

---

# Part II: Advanced Chained Attack Analysis

## Protocol Architecture — Trust Model Deep Dive

Before presenting attack chains, it is essential to understand the trust architecture of the RustDesk protocol. The system has four actors:

1. **Client** (connecting peer) — initiates connection
2. **Server** (target peer) — accepts connection, shares screen/input
3. **Rendezvous Server (RS)** — routes connections, signs peer identity
4. **Relay Server** — forwards traffic when direct connection fails

### The Rendezvous Server is the Sole Root of Trust

The RS is the **only** entity that vouches for peer identity. The trust chain works as follows:

1. Each RustDesk instance registers with the RS, providing its ID and signing public key
2. The RS signs the peer's `{ID, PublicKey}` tuple with its own signing key
3. When Client wants to connect to Server, the RS provides the Server's signed `{ID, PK}` in the `PunchHoleResponse.pk` field (`src/client.rs:506`)
4. Client verifies this signature against the RS's public key (`src/client.rs:770`)
5. Client uses the verified PK to authenticate the Server's `SignedId` message (`src/client.rs:794`)
6. Only then is a symmetric key established (`src/client.rs:796-805`)

**Critical implication**: Whoever controls the RS controls ALL peer identity verification. There is no independent certificate authority, no certificate pinning to the peer, and no out-of-band verification.

### Key Exchange Protocol Flow (Detailed)

```
CLIENT                        RS                          SERVER
  |---[PunchHoleRequest]----->|                              |
  |                           |---[PunchHole]--------------->|
  |                           |<--[PunchHoleResponse]--------|
  |<--[PunchHoleResponse]----|                               |
  |    (contains signed_id_pk = RS_sign(Server_ID + Server_PK))
  |                                                          |
  |================== Direct/Relay TCP =====================>|
  |                                                          |
  |<-----------[SignedId: Server_sign(Server_ID + EphPK)]---|
  |   (client verifies using Server_PK from step above)      |
  |                                                          |
  |---[PublicKey: EphPK_client + box_seal(symkey)]---------->|
  |   (server decrypts symkey using EphSK)                   |
  |                                                          |
  |<============= Encrypted with symkey ===================>|
  |                                                          |
  |<-----------[Hash: {salt, challenge}]--------------------|
  |---[LoginRequest: {password_hash, my_id, ...}]---------->|
  |<-----------[LoginResponse / Error]----------------------|
```

---

## FINDING 13 (CRITICAL): Protocol Downgrade — Encryption Silently Disabled on PK Mismatch

**File:** `src/client.rs:810-816` (client), `src/server.rs:227-229` (server)
**Impact:** Active network attacker can force ALL connections to be completely unencrypted
**Type:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)

### The Client Side

When the Server's `SignedId` fails signature verification, the client **silently falls back to unencrypted** instead of aborting:

```rust
// src/client.rs:810-816
} else {
    // fall back to non-secure connection in case pk mismatch
    log::info!("pk mismatch, fall back to non-secure");
    let mut msg_out = Message::new();
    msg_out.set_public_key(PublicKey::new());  // EMPTY PublicKey
    conn.send(&msg_out).await?;
}
```

Additionally, when `signed_id_pk` is empty (RS didn't provide peer identity), the client skips encryption entirely:

```rust
// src/client.rs:781-787
let sign_pk = match sign_pk {
    Some(v) => v,
    None => {
        // send an empty message out
        conn.send(&Message::new()).await?;
        return Ok(option_pk);  // Returns OK — no error!
    }
};
```

### The Server Side

When the server receives an empty `PublicKey` from the client:

```rust
// src/server.rs:227-229
} else if pk.asymmetric_value.is_empty() {
    Config::set_key_confirmed(false);
    log::info!("Force to update pk");
}
// Connection proceeds WITHOUT encryption
```

The server not only continues without encryption but also **invalidates its key confirmation**, forcing a key re-registration — which could cause further issues.

### Attack Execution

1. Attacker positions as network MITM (ARP spoof, rogue WiFi, BGP hijack, etc.)
2. When Client connects to RS, attacker modifies the `PunchHoleResponse` to strip the `pk` field (set to empty)
3. Client's `secure_connection()` enters the `sign_pk == None` branch → no encryption
4. Client sends an empty `Message` instead of a `PublicKey`
5. Server receives the empty message, has no `PublicKey` union → no encryption set
6. **Both sides silently proceed with plaintext communication**
7. Attacker reads all screen data, keystrokes, file transfers, and clipboard in real-time
8. Attacker can inject messages into the stream (input events, file data, etc.)

### Why This Is Critical

- Neither side warns the user that encryption was downgraded
- The connection appears to work normally from both perspectives
- There is no "secure connection indicator" the user can check
- The log message "pk mismatch, fall back to non-secure" goes to the log file, not the UI

---

## FINDING 14 (CRITICAL): SyncConfig via IPC — Complete Configuration Replacement

**File:** `src/ipc.rs:709-714`
**Impact:** Any local user can replace the ENTIRE service configuration in a single operation
**Type:** CWE-732 + CWE-862 (Missing Authorization)

### Description

The IPC handler processes `Data::SyncConfig` which replaces ALL configuration atomically:

```rust
// src/ipc.rs:709-714
Data::SyncConfig(Some(configs)) => {
    let (config, config2) = *configs;
    let _chk = CheckIfRestart::new();
    Config::set(config);      // Replaces ENTIRE Config
    Config2::set(config2);    // Replaces ENTIRE Config2
}
```

This is not individual option setting — this replaces the entire serialized Config struct, which includes:
- `rendezvous-server` (which RS to connect to)
- `key-pair` (the device's signing keypair!)
- `key-confirmed` (whether the RS has the correct PK)
- `salt` (used in password hashing)
- `permanent-password`
- ALL options (2FA, access mode, permissions, etc.)

### Attack Impact

An attacker can replace the device's keypair with one they control. Since the keypair is used to sign the `SignedId` message during peer-to-peer key exchange, this means:
1. The attacker generates a new keypair
2. Sets it via `Data::SyncConfig`
3. The server now signs `SignedId` with the attacker's private key
4. The attacker can predict/derive the symmetric session key
5. Even "encrypted" connections are now attacker-readable

---

## COMPLETE ATTACK CHAIN A: Local Shell → Full MITM of All Remote Connections

**Entry Point:** Any unprivileged local shell access
**End Result:** Persistent MITM of ALL remote desktop connections to/from the target device
**Affected:** Every user who connects to or from this machine

### Step-by-Step

```
Phase 1: IPC Access (0 seconds)
├─ Connect to /tmp/rustdesk_ipc or equivalent
├─ Socket permissions are 0o0777 — no restrictions
└─ No authentication on IPC channel

Phase 2: Configuration Poisoning (< 1 second)
├─ Send: Data::SyncConfig(Some((modified_config, config2)))
│   Where modified_config contains:
│   ├─ custom-rendezvous-server = "attacker-rs.evil.com:21116"
│   ├─ key = base64(attacker_rs_public_key)
│   ├─ key-pair = (attacker_signing_sk, attacker_signing_pk)
│   ├─ key-confirmed = true
│   └─ All other settings preserved from original
└─ Config is written to disk immediately — survives reboots

Phase 3: Service Restart (< 5 seconds)
├─ Send: Data::Close via IPC
├─ Service stops (if systemd: auto-restarts)
└─ Service reconnects to attacker's RS

Phase 4: Attacker's Rendezvous Server (persistent)
├─ Receives RegisterPeer from target device
├─ Now controls connection routing for this device ID
├─ For each incoming PunchHoleRequest:
│   ├─ Signs attacker-controlled {ID, PK} with attacker's RS key
│   ├─ Client verifies signature → PASSES (using configured RS key)
│   └─ Routes connection through attacker's relay
└─ Full MITM established

Phase 5: Interception Capabilities (ongoing)
├─ See all screen content in real-time (video frames)
├─ See all keyboard input (including passwords)
├─ See all mouse movements
├─ See all file transfers (both directions)
├─ See all clipboard operations
├─ Inject keyboard/mouse input
├─ Modify file transfers in transit
└─ Impersonate either peer to the other
```

### Evidence Trail

| Code Location | Evidence |
|---|---|
| `src/ipc.rs:442-443` | Socket permissions `0o0777` |
| `src/ipc.rs:433` | `SecurityAttributes::allow_everyone_create()` |
| `src/ipc.rs:709-714` | `Config::set(config)` — full config replacement |
| `src/ipc.rs:538-574` | `Data::Close` — service termination |
| `src/client.rs:424-428` | `secure_tcp` uses configured `key` to verify RS |
| `src/client.rs:770` | `decode_id_pk(&signed_id_pk, &rs_pk)` — uses RS PK from config |
| `src/server.rs:194` | `Config::get_key_pair()` — uses keypair from config |
| `src/server.rs:201-212` | Server signs with configured keypair |

---

## COMPLETE ATTACK CHAIN B: Local Shell → Steal Credentials → Bypass All Auth → Remote Shell

**Entry Point:** Any unprivileged local shell access
**End Result:** Full remote access from anywhere on the internet, bypassing password + 2FA
**Affected:** The target machine, all its data, internal network

### Step-by-Step

```
Phase 1: Credential Extraction via IPC (< 1 second)
├─ Send: Data::Config { name: "permanent-password", value: None }
│   → Receive: permanent password in cleartext
├─ Send: Data::Config { name: "salt", value: None }
│   → Receive: password salt
├─ Send: Data::Config { name: "id", value: None }
│   → Receive: device ID (e.g., "123 456 789")
├─ Send: Data::Options(None)
│   → Receive: all options including "2fa" config
└─ Send: Data::ConfirmedKey(None)
    → Receive: key pair (signing keys)

Phase 2: 2FA Bypass (< 1 second)
├─ Extract encrypted TOTP secret from "2fa" option value
├─ Decrypt using hardcoded key "00":
│   decrypt_vec_or_original(&secret, "00")  [src/auth_2fa.rs:66]
├─ Reconstruct TOTP generator:
│   TOTP(SHA1, digits=6, period=30, secret)
└─ Generate valid 2FA code at any time

Phase 3: Remote Connection (from anywhere)
├─ Install RustDesk client on attacker machine
├─ Connect to device ID obtained in Phase 1
├─ Provide stolen permanent password
├─ Provide generated 2FA code
└─ Full authenticated session established

Phase 4: Exploitation
├─ Full screen access (see everything user sees)
├─ Keyboard/mouse control (act as the user)
├─ Terminal access (if enabled — full shell)
├─ File transfer (exfiltrate any file)
├─ Port forwarding → internal network pivoting:
│   ├─ 169.254.169.254:80 → cloud metadata/credentials
│   ├─ 10.0.0.x:5432 → PostgreSQL databases
│   ├─ 10.0.0.x:6379 → Redis caches
│   └─ 10.0.0.x:22 → SSH to other machines
└─ Clipboard interception (capture copied passwords, tokens)
```

### Self-Healing Property

Even if the user changes their password:
1. Attacker still has IPC access (socket permissions are code-level, not user-configurable)
2. Attacker reads the new password via IPC
3. New 2FA code generated from the same TOTP secret
4. Access is immediately re-established

The only remediation is modifying the source code to fix the IPC permissions.

---

## COMPLETE ATTACK CHAIN C: Network Attacker → Protocol Downgrade → Plaintext Interception

**Entry Point:** Network adjacency (same WiFi, ISP-level, BGP, etc.)
**End Result:** All remote desktop traffic in plaintext
**Affected:** Any connection traversing the attacker's network segment

### Step-by-Step

```
Phase 1: Position as MITM
├─ ARP spoofing (local network)
├─ Rogue WiFi access point
├─ DNS poisoning
├─ BGP hijacking (ISP/nation-state level)
└─ Compromised router/switch

Phase 2: Intercept Client→RS Connection
├─ Client connects to RS via TCP
├─ If key/token are empty: secure_tcp() is NOT called
│   [src/client.rs:424-428]
├─ Even if secure_tcp IS called: attacker can block it
│   and let the connection fall through
└─ Client sends PunchHoleRequest

Phase 3: Modify PunchHoleResponse
├─ Intercept RS's PunchHoleResponse
├─ Strip the 'pk' field (set to empty bytes)
├─ Forward modified response to client
└─ Client receives response with empty signed_id_pk

Phase 4: Client-Side Downgrade
├─ secure_connection() called with empty signed_id_pk
├─ sign_pk = None (no RS signature to verify)
├─ Code path: src/client.rs:782-787
│   → sends empty Message
│   → returns Ok(None) — NO ERROR
└─ Connection has NO encryption key set

Phase 5: Server-Side Downgrade
├─ Server's create_tcp_connection() [src/server.rs:195]
│   sends SignedId with signed ephemeral key
├─ Client doesn't respond with PublicKey (sent empty Message earlier)
│   OR client responds with empty PublicKey
├─ Server: src/server.rs:227-229
│   → pk.asymmetric_value.is_empty()
│   → Config::set_key_confirmed(false)
│   → continues without encryption
└─ Session proceeds in PLAINTEXT

Phase 6: Traffic Interception
├─ Hash challenge/response visible in plaintext
│   → Attacker captures SHA256(SHA256(password+salt)+challenge)
│   → Can perform offline dictionary attack against password
├─ All screen frames visible (video codec data)
├─ All keyboard input visible (including typed passwords)
├─ All file transfers visible
├─ All clipboard data visible
└─ Can inject arbitrary protocol messages
```

### Why This Works

The protocol has **no mandatory encryption**. Encryption is "best effort":
- If the RS provides peer PK → encrypted
- If the RS doesn't provide PK → unencrypted, silently
- If PK verification fails → unencrypted, silently
- No user notification either way

---

## COMPLETE ATTACK CHAIN D: Persistent Config Backdoor — Survives Everything

**Entry Point:** One-time local shell access (any user)
**End Result:** Permanent invisible backdoor that survives password changes, 2FA changes, and reboots
**Affected:** Target machine permanently compromised

### Step-by-Step

```
Phase 1: Deploy Backdoor Configuration (one-time, < 2 seconds)
Via IPC send Data::Options(Some({...})):
├─ "permanent-password" → set to attacker-known value
├─ "access-mode" → "full" (all permissions enabled)
├─ "2fa" → "" (disable 2FA)
├─ "approve-mode" → "password" (no click-to-approve needed)
├─ "enable-file-transfer" → "Y"
├─ "enable-tunnel" → "Y"  (port forwarding)
├─ "enable-terminal" → "Y" (remote shell)
├─ "allow-auto-record-incoming" → "N" (disable session recording)
├─ "enable-lan-discovery" → "N" (reduce visibility)
└─ "stop-service" → "" (ensure service stays running)

Phase 2: Disable Security Notifications
├─ "enable-audio" → "N" (no audio alerts)
├─ Clear trusted devices: Data::ClearTrustedDevices
└─ All changes written to config file immediately

Phase 3: Access From Anywhere (ongoing)
├─ Connect to device ID with known password
├─ No 2FA required (disabled)
├─ No click-to-approve required (password mode only)
├─ Full permissions: screen, keyboard, files, terminal, tunnel
└─ No session recording

Phase 4: Self-Healing After User Password Change
├─ User changes password through RustDesk GUI
├─ New password is written to config
├─ Attacker reads new password via IPC (still world-accessible)
│   Data::Config { name: "permanent-password", value: None }
└─ Attacker updates their stored password — access continues

Phase 5: Self-Healing After 2FA Enable
├─ User enables 2FA through RustDesk GUI
├─ 2FA secret written to config with hardcoded key "00"
├─ Attacker reads via IPC: Data::Options(None) → "2fa" value
├─ Decrypt with "00", generate TOTP codes
└─ 2FA defeated — access continues

Phase 6: Self-Healing After Service Reinstall
├─ IPC permissions are hardcoded in source (0o0777)
├─ Reinstalling RustDesk recreates the same vulnerable socket
└─ Attacker repeats Phase 1 — access continues
```

### The Only Effective Remediation

The IPC socket permissions must be changed in the source code. No amount of user-level configuration, password rotation, or 2FA enablement can defend against this because the attacker retains the ability to read all credentials and modify all settings through the world-accessible IPC socket.

---

## COMPLETE ATTACK CHAIN E: Cross-Privilege Escalation via SwitchSides + Relay Manipulation

**Entry Point:** Authenticated remote session (via Chain B)
**End Result:** Control of the connecting user's machine (privilege escalation across hosts)
**Affected:** Any administrator who connects to the compromised machine

### Concept

RustDesk's "Switch Sides" feature allows the controlled machine to reverse roles and control the controller. This is triggered via IPC:

```rust
// src/ipc.rs:738-745
Data::SwitchSidesRequest(id) => {
    let uuid = uuid::Uuid::new_v4();
    crate::server::insert_switch_sides_uuid(id, uuid.clone());
```

### Attack Scenario

1. IT administrator connects to a compromised machine for maintenance
2. Attacker (who has IPC access on compromised machine) sends `Data::SwitchSidesRequest`
3. The compromised machine initiates a reverse connection to the admin's machine
4. If the admin's machine auto-accepts (e.g., the session is already trusted), attacker gains control
5. Now the attacker has desktop access to the administrator's machine
6. From the admin's machine: domain controller access, credential harvesting, network-wide compromise

---

## Impact Assessment: Cascading Failure Model

```
Local Shell Access (any user)
         │
         ▼
    IPC Socket (0o0777)
    ┌────┴─────────────────────────────────────────────┐
    │                                                   │
    ▼                                                   ▼
Read Credentials                              Modify Configuration
├─ Permanent Password                         ├─ Redirect to Rogue RS
├─ Temporary Password                         ├─ Replace Signing Keypair
├─ Salt                                       ├─ Disable 2FA
├─ Signing Keypair                            ├─ Disable Approve Mode
├─ 2FA Secret (hardcoded key)                 ├─ Enable All Permissions
└─ Device ID                                  ├─ Enable Insecure TLS
         │                                    └─ Set Known Password
         ▼                                             │
    Remote Access                                      ▼
    (from anywhere)                             MITM All Connections
    ├─ Full Desktop Control                     ├─ See All Screens
    ├─ Terminal/Shell                            ├─ Capture All Keystrokes
    ├─ File Exfiltration                        ├─ Intercept File Transfers
    ├─ Clipboard Capture                        └─ Impersonate Any Peer
    └─ Port Forwarding (SSRF)                          │
         │                                             ▼
         ▼                                    Compromise ALL Users
    Internal Network                           Connected To This Device
    ├─ Cloud Metadata
    ├─ Databases
    ├─ Internal Services
    └─ Lateral Movement
```

This represents a **complete cascading failure** where a single design decision (world-accessible IPC socket) combined with protocol-level weaknesses (no mandatory encryption, hardcoded crypto keys, signature bypass) enables an unprivileged local user to escalate to full control of the target machine, all connected users, and the internal network.

---

## Methodology

This audit was conducted through static code analysis of the RustDesk source code. The review focused on:
- All network-facing code (listeners, protocol handlers, connection management)
- Authentication and authorization mechanisms
- IPC and inter-process communication
- File system operations and path handling
- Cryptographic implementations
- Platform-specific privilege management (Windows, Linux, macOS)
- Command execution and shell interaction
- Plugin/extension mechanisms
- Configuration handling and input validation
- **End-to-end protocol analysis**: Complete tracing of the connection lifecycle from rendezvous to key exchange to authentication to session establishment
- **Trust model analysis**: Identification of all trust roots and trust boundaries
- **Attack chain composition**: Building multi-step attacks that chain individual weaknesses

## Scope Notes

- The `libs/hbb_common` submodule was not initialized, limiting review of the common library. The `password_security`, `config`, and `fs` modules referenced throughout the code could contain additional issues.
- Flutter/Dart UI code was not reviewed in depth (focus was on the Rust backend).
- This is a static analysis only; no dynamic testing or fuzzing was performed.
- The `AddrMangle` encoding/decoding in `hbb_common` was not auditable (submodule not available), but if address encoding is predictable, additional attacks on connection routing may be possible.

---

# Part III: Zero-Access Remote Attack Chains

## The Premise

Parts I and II assumed some form of local access (unprivileged shell) to exploit the IPC socket. This section answers: **what can an attacker do with absolutely zero prior access** — no local shell, no physical access, no credentials, no network adjacency?

## External Attack Surface Inventory

RustDesk exposes the following services to the network:

| # | Service | Protocol | Bind Address | Default Port | Auth Required |
|---|---------|----------|-------------|-------------|---------------|
| 1 | **Direct Server** | TCP | `0.0.0.0` | `RENDEZVOUS_PORT + 2` (21118) | LoginRequest (password) |
| 2 | **LAN Discovery** | UDP | `0.0.0.0` | `RENDEZVOUS_PORT + 3` (21119) | **None** |
| 3 | **Port Forward Listener** | TCP | `0.0.0.0` | User-configured | Per-session auth |
| 4 | **Rendezvous UDP** | UDP | Ephemeral | Outbound to RS | RS-level |
| 5 | **Rendezvous TCP** | TCP | Ephemeral | Outbound to RS | RS-level |

---

## FINDING 15 (HIGH): Direct Server Port Has No Encryption — All Traffic in Plaintext

**File:** `src/rendezvous_mediator.rs:810-817`
**Impact:** Any remote connection to the direct-access port operates without encryption
**Type:** CWE-319 (Cleartext Transmission of Sensitive Information)

### Description

The direct server spawns connections with `secure: false`:

```rust
// src/rendezvous_mediator.rs:810-817
crate::server::create_tcp_connection(
    server,
    hbb_common::Stream::from(stream, local_addr),
    addr,
    false,      // ← secure = false — NEVER encrypted
    None,
)
```

In `create_tcp_connection()` (`src/server.rs:195`), the encryption setup is gated on `secure`:

```rust
if secure && pk.len() == sign::PUBLICKEYBYTES ... {
    // key exchange happens here
}
// If !secure: Connection::start() runs with NO encryption
```

### Consequences

Any connection to port 21118 (default) transmits in cleartext:
- The password challenge/response (SHA256-hashed, but captured hash enables offline brute force)
- ALL screen frames (video codec data)
- ALL keyboard input (including passwords typed in the remote session)
- ALL file transfers
- ALL clipboard content

An eavesdropper on ANY network hop between the attacker and target sees everything.

---

## FINDING 16 (HIGH): Pre-Authentication SSRF via Port Forward — Internal Network Port Scanner

**File:** `src/server/connection.rs:2175-2207`
**Impact:** Unauthenticated remote attacker can scan internal network ports through the RustDesk host
**Type:** CWE-918 (Server-Side Request Forgery) + CWE-209 (Error Message Information Leak)

### Description

When a `LoginRequest` with a `PortForward` union arrives, the server processes it in this order:

```
Step 1: handle_login_request_without_validation()     [line 2101] — NO password check
Step 2: Permission check (tunnel enabled?)             [line 2176] — passes if default config
Step 3: TcpStream::connect(attacker-controlled-addr)   [line 2192] — BEFORE password check
Step 4: Password validation                            [line 2293] — happens AFTER the connect
```

The critical code:

```rust
// src/server/connection.rs:2190-2207
let mut addr = format!("{}:{}", pf.host, pf.port);
self.port_forward_address = addr.clone();
match timeout(3000, TcpStream::connect(&addr)).await {
    Ok(Ok(sock)) => {
        self.port_forward_socket = Some(Framed::new(sock, BytesCodec::new()));
    }
    _ => {
        self.send_login_error(format!(
            "Failed to access remote {}, please make sure if it is open",
            addr                            // ← LEAKS the address back
        )).await;
        return false;                       // ← Returns BEFORE password check
    }
}
// ... password check happens much later at line 2293 ...
```

### The Oracle

The server returns **different error messages** depending on whether the internal port is open or closed:

| Internal Port State | Server Response | Password Checked? |
|---|---|---|
| **Closed/Filtered** | `"Failed to access remote {host}:{port}"` | **No** — returns before password check |
| **Open** | `"Password wrong"` (or other auth error) | **Yes** — password check happens |

### Attack Execution

```
Attacker (Internet)                    RustDesk Host (port 21118)          Internal Network
      │                                        │                                │
      │──[TCP Connect]────────────────────────>│                                │
      │<─[Hash{salt, challenge}]──────────────│                                │
      │                                        │                                │
      │──[LoginRequest{                        │                                │
      │    PortForward{                        │                                │
      │      host: "10.0.0.5",                 │                                │
      │      port: 5432                        │──[TCP Connect]────────────────>│
      │    },                                  │     (PostgreSQL)               │
      │    password: "anything"                │<─[RST or SYN-ACK]────────────│
      │  }]──────────────────────────────────>│                                │
      │                                        │                                │
      │<─[Error: "Failed to access..." OR      │                                │
      │   Error: "Password wrong"]────────────│                                │
      │                                        │                                │
      │  (Different errors = port scan oracle) │                                │
```

### What Can Be Scanned

- `localhost` services (databases, web servers, admin panels)
- Cloud metadata endpoints (`169.254.169.254:80` for AWS/GCP/Azure)
- Internal RFC1918 networks (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`)
- Adjacent infrastructure (monitoring, CI/CD, credentials vaults)
- The 3-second timeout also provides timing information (open vs filtered)

### No Authentication Required

- The `host` and `port` are entirely attacker-controlled
- The permission check at line 2176 passes with default configuration (`access-mode: "full"`)
- The `control_permissions` is `None` for direct connections (line 816 of rendezvous_mediator.rs)
- The only rate limit is the login failure counter, which isn't incremented for port-scan failures (the function returns before password validation)

---

## FINDING 17 (MEDIUM): LAN Discovery Leaks Device Identity Without Authentication

**File:** `src/lan.rs:44-65`
**Impact:** Any device on the LAN can enumerate all RustDesk instances and their identities
**Type:** CWE-200 (Information Exposure)

### Description

The LAN discovery listener responds to UDP "ping" broadcasts with full device information:

```rust
// src/lan.rs:55-63
let peer = PeerDiscovery {
    cmd: "pong".to_owned(),
    mac: get_mac(&self_addr),        // MAC address
    id,                               // RustDesk device ID
    hostname,                         // System hostname
    username: crate::platform::get_active_username(),  // Logged-in username
    platform: whoami::platform().to_string(),          // OS (Linux/Windows/macOS)
    ..Default::default()
};
```

**No authentication whatsoever.** Any device that sends a UDP packet to port 21119 receives:

| Field | Value | Attacker Use |
|---|---|---|
| `id` | Device ID (e.g., "123 456 789") | Connect to this device via RS or direct port |
| `hostname` | System hostname | Identify high-value targets (e.g., "dc01", "db-prod") |
| `username` | Active user | Social engineering, identify admin accounts |
| `platform` | OS type | Select platform-specific exploits |
| `mac` | MAC address | Network fingerprinting, ARP spoofing target |

### Attack Use

1. Send UDP broadcast to port 21119 on the LAN
2. Collect all RustDesk device IDs, hostnames, usernames
3. Use the device IDs to connect via the direct server port (21118)
4. Use the hostname/username information for targeted social engineering
5. Use MAC addresses for ARP spoofing to position as MITM

---

## FINDING 18 (HIGH): Distributed Password Brute-Force with In-Memory Rate Limits

**File:** `src/server/connection.rs:3412-3461`
**Impact:** Rate limits are per-IP, in-memory, and reset on service restart — distributed attacks feasible
**Type:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

### Rate Limiting Analysis

```rust
// src/server/connection.rs:3436-3459
let res = if failure.2 > 30 {                          // 30 total attempts lifetime
    "Too many wrong attempts"
} else if time == failure.0 && failure.1 > 6 {         // 6 attempts per minute
    "Please try 1 minute later"
} else {
    true  // Allow attempt
};
```

### Weaknesses

| Property | Value | Weakness |
|---|---|---|
| Per-minute limit | 6 attempts/IP | Distributed across N IPs = 6N/minute |
| Lifetime limit | 30 attempts/IP | Trivially bypassed with new IPs |
| Storage | `lazy_static` HashMap (in-memory) | **Resets on service restart** |
| IPv6 handling | /64=60, /56=80, /48=100 limits | Still high thresholds per prefix |
| Password space | User-chosen passwords | Often weak (6-8 character, predictable) |

### Attack Math

With the direct server port (21118), connection is unencrypted:

```
Botnet of 1,000 IPs:
- 6,000 password attempts per minute
- 360,000 per hour
- 8,640,000 per day

Common password lists:
- rockyou.txt top 10,000: cracked in ~2 minutes
- rockyou.txt full (14M): cracked in ~2 days

Service restart (crash/OOM/deliberate):
- All rate limit counters reset to zero
- Attacker can trigger restart via connection flooding → OOM
```

### The Unencrypted Channel Advantage

Because the direct server port uses **no encryption** (Finding 15), an eavesdropper who captures even ONE successful authentication can:
1. Capture `Hash{salt, challenge}` and the login response
2. Capture `SHA256(SHA256(password + salt) + challenge)` from the LoginRequest
3. Perform offline dictionary attack against the captured hash
4. No more brute-force needed — single capture is sufficient

---

## COMPLETE ZERO-ACCESS ATTACK CHAIN F: Internet → Port Scan → Password Crack → Full Compromise

**Entry Point:** Internet access only — zero credentials, zero local access
**End Result:** Full remote desktop control, terminal access, file exfiltration, internal network pivoting

```
Phase 1: Reconnaissance (automated, <1 minute per target)
├─ Masscan/zmap for port 21118 across target IP range
├─ For each responding host: confirmed RustDesk instance
├─ If on same LAN: UDP broadcast to port 21119
│   → Receive: device ID, hostname, username, platform, MAC
└─ Identify high-value targets by hostname/username

Phase 2: Internal Network Mapping via Pre-Auth SSRF (no credentials needed)
├─ Connect to port 21118
├─ Receive Hash{salt, challenge}
├─ Send LoginRequest with PortForward{host: "169.254.169.254", port: 80}
│   → "Failed to access remote..." = cloud metadata blocked
│   → "Password wrong" = cloud metadata endpoint REACHABLE
├─ Scan common internal ranges:
│   ├─ 10.0.0.1-254:22     (SSH)
│   ├─ 10.0.0.1-254:3389   (RDP)
│   ├─ 10.0.0.1-254:5432   (PostgreSQL)
│   ├─ 10.0.0.1-254:6379   (Redis)
│   ├─ 10.0.0.1-254:8080   (Web admin)
│   ├─ 10.0.0.1-254:9200   (Elasticsearch)
│   └─ 127.0.0.1:*          (localhost services)
├─ Rate limit does NOT apply (failures return before password check)
└─ Result: complete map of internal network services

Phase 3: Password Brute-Force (distributed, hours to days)
├─ Direct server connection = UNENCRYPTED (secure: false)
├─ Distribute across botnet IPs (6 attempts/minute/IP)
├─ Or: capture ONE legitimate login from network (passive sniffing)
│   → Offline dictionary attack against SHA256 hash
├─ Common passwords cracked quickly:
│   Top 10K passwords: ~2 minutes with 1K IPs
│   Full rockyou: ~2 days with 1K IPs
└─ Password found → proceed to Phase 4

Phase 4: Full Compromise (immediate)
├─ Connect to port 21118 with cracked password
├─ Full remote desktop: see screen, control keyboard/mouse
├─ If terminal enabled: full shell access
├─ If file transfer enabled: exfiltrate any data
├─ If tunnel enabled: port forward to internal services found in Phase 2
│   ├─ Connect to internal databases directly
│   ├─ Connect to cloud metadata → steal cloud credentials
│   ├─ Connect to internal web admin panels
│   └─ Pivot to additional machines
└─ All traffic UNENCRYPTED on the wire (direct port, secure=false)

Phase 5: Persistence (post-compromise)
├─ Via terminal: install backdoor, create accounts
├─ Via IPC socket (now accessible locally):
│   ├─ Read/set permanent password
│   ├─ Disable 2FA
│   ├─ Redirect to attacker's RS
│   └─ Full config control (see Part II chains)
└─ Persistent access established
```

---

## COMPLETE ZERO-ACCESS ATTACK CHAIN G: Compromised Public Rendezvous Server → Mass Surveillance

**Entry Point:** Compromise of a public RustDesk rendezvous server
**End Result:** MITM capability over ALL devices registered to that server
**Affected:** Every RustDesk user using the compromised RS

### Background

RustDesk's trust model places the rendezvous server as the **sole root of trust** for peer identity:
- The RS signs `{peer_ID, peer_PublicKey}` tuples (`src/client.rs:770`)
- Clients verify these signatures against the RS's public key
- There is NO independent verification of peer identity (no certificate pinning, no TOFU, no out-of-band check)

### Attack Steps

```
Phase 1: RS Compromise
├─ Compromise a public RS (rs-ny.rustdesk.com, etc.)
│   via: software vulnerability, credential theft, insider, supply chain
├─ Obtain the RS's signing private key
└─ All registered devices trust this key for peer identity

Phase 2: Selective MITM
├─ When Client A requests connection to Device B:
│   ├─ RS normally provides: RS_sign(B_ID + B_PublicKey)
│   ├─ Attacker substitutes: RS_sign(B_ID + Attacker_PublicKey)
│   ├─ Client A verifies signature → PASSES (RS key is legitimate)
│   └─ Client A establishes encrypted channel with Attacker, not Device B
├─ Attacker separately connects to Device B as a normal client
├─ Attacker relays traffic between A and B (transparent MITM)
└─ Neither party detects the interception

Phase 3: Capabilities
├─ Read all screen content in real-time
├─ Read all keyboard input (including credentials)
├─ Read all file transfers
├─ Read all clipboard operations
├─ Inject keyboard/mouse input into either direction
├─ Modify file transfers in transit
├─ Selectively drop or delay messages
└─ Record sessions for later analysis

Phase 4: Scale
├─ This affects ALL connections routed through the compromised RS
├─ Could be tens of thousands of devices
├─ Attack is selective (can target specific device IDs)
├─ No client-side indicator of compromise
└─ Persists until RS is re-secured and all clients get new RS keys
```

### Why There Is No Defense

The protocol has no mechanism for:
- Peer certificate pinning (remembering a peer's key from previous connections)
- Trust-on-first-use (TOFU) for peer identity
- Out-of-band peer key verification
- Client notification when a peer's key changes
- Multiple signature verification (requiring >1 RS to agree)

---

## COMPLETE ZERO-ACCESS ATTACK CHAIN H: DNS Poisoning → Session Hijack

**Entry Point:** DNS poisoning capability (local network, ISP, or registrar level)
**End Result:** Redirect all connections through attacker-controlled infrastructure

```
Phase 1: DNS Poisoning
├─ Target: the domain name configured as custom-rendezvous-server
│   (or the default rs-ny.rustdesk.com / rs-sg.rustdesk.com)
├─ Methods: DNS cache poisoning, rogue DHCP, compromised resolver,
│   registrar account takeover, BGP hijack of DNS server
└─ Result: domain resolves to attacker's IP

Phase 2: Fake Rendezvous Server
├─ Attacker runs a rendezvous server on their IP
├─ Critical question: does the client verify the RS's key?
│
├─ Case A: Custom RS with key configured
│   ├─ secure_tcp() verifies RS key via signature
│   ├─ Attacker needs the RS's private key → attack BLOCKED
│   └─ (unless combined with IPC access to change the key)
│
├─ Case B: Custom RS without key configured (key is empty)
│   ├─ src/client.rs:424-428: secure_tcp only called if
│   │   key AND token are both non-empty
│   ├─ If key is empty: NO secure_tcp → plaintext RS connection
│   ├─ Attacker's fake RS receives plaintext PunchHoleRequest
│   ├─ Attacker routes connection through their relay
│   └─ Combined with protocol downgrade: full MITM
│
└─ Case C: Default public RS
    ├─ Uses hardcoded RS_PUB_KEY (config::RS_PUB_KEY)
    ├─ Attacker needs the official RS private key → attack BLOCKED
    └─ (unless public RS is compromised — see Chain G)

Phase 3: Impact (for Case B — custom RS without key)
├─ All devices using this RS are redirected to attacker
├─ Attacker controls connection routing
├─ Combined with protocol downgrade (Finding 13): all traffic plaintext
└─ Full surveillance and injection capability
```

---

## External Attack Surface Summary

```
                    INTERNET
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
   Port 21118     DNS/Network     Rendezvous
  (Direct TCP)     Attacks       Server Trust
        │              │              │
        ├─ UNENCRYPTED │              │
        │  (secure=    │              │
        │   false)     │              │
        │              │              │
        ├─ Pre-auth    ├─ DNS poison  ├─ If RS
        │  SSRF/port   │  → redirect  │  compromised:
        │  scanner     │  RS traffic   │  MITM all
        │  (Finding    │              │  connections
        │   16)        ├─ Protocol    │
        │              │  downgrade   ├─ Sign any
        ├─ Password    │  (Finding    │  peer identity
        │  brute-force │   13)        │
        │  distributed │              ├─ Route to
        │  (Finding    │              │  attacker
        │   18)        │              │  relay
        │              │              │
        ├─ Traffic     │              │
        │  eavesdrop   │              │
        │  → offline   │              │
        │  hash crack  │              │
        │              │              │
        ▼              ▼              ▼
   FULL REMOTE     FULL MITM      MASS
   DESKTOP         OF SESSION     SURVEILLANCE
   CONTROL                        OF ALL USERS
```

### Key Insight: No Local Access Required

The direct server port (21118) is the primary zero-access vector because:
1. It binds to `0.0.0.0` — reachable from the internet
2. It passes `secure: false` — zero encryption, ever
3. It processes `PortForward` TCP connections before password validation — pre-auth SSRF
4. Its rate limiting is per-IP and in-memory — trivially bypassed with distribution or restart
5. The captured password hash can be cracked offline from a single eavesdropped session

---

# Part IV: End-to-End Validated Attack — Zero to Root Shell (Every Code Path Traced)

This section traces, step by step, every function call from an internet attacker with zero prior access through to a root shell on the target machine. Every claim is backed by an exact code location.

## Prerequisites

- Target: A machine running RustDesk service (as root/SYSTEM, typical for systemd/Windows service)
- Attacker: Internet access to port 21118 on the target
- Configuration: Default settings (direct server enabled, terminal enabled, access-mode "full")
- No credentials, no local access, no network adjacency needed

## Step 0: Port Scan — Discover Target

The direct server binds to all interfaces:

```
src/rendezvous_mediator.rs:772
  hbb_common::tcp::listen_any(port as _)    // 0.0.0.0:21118
```

Attacker runs: `nmap -p 21118 <target_range>` → identifies RustDesk instances.

## Step 1: TCP Connect — Enter `create_tcp_connection`

```
src/rendezvous_mediator.rs:802
  if let Ok(Ok((stream, addr))) = hbb_common::timeout(1000, l.accept()).await

src/rendezvous_mediator.rs:810-817
  crate::server::create_tcp_connection(
      server,
      hbb_common::Stream::from(stream, local_addr),
      addr,
      false,     // ← CRITICAL: secure = false
      None,      // ← no control_permissions
  )
```

**Validated:** `secure=false` → no encryption setup ever occurs. Proceeds to:

```
src/server.rs:195
  if secure && pk.len() == sign::PUBLICKEYBYTES ...  // false && ... = never entered
```

Key exchange is ENTIRELY SKIPPED. The stream has no encryption key.

## Step 2: `Connection::start` → `on_open` — Receive Challenge

```
src/server/connection.rs:363-367
  let hash = Hash {
      salt: Config::get_salt(),                  // from config file
      challenge: Config::get_auto_password(6),   // random 6-char string
      ..Default::default()
  };

src/server/connection.rs:484
  if !conn.on_open(addr).await { ... }

src/server/connection.rs:1229-1231  (inside on_open)
  let mut msg_out = Message::new();
  msg_out.set_hash(self.hash.clone());
  self.send(msg_out).await;            // ← Sent to attacker in PLAINTEXT
```

**What the attacker receives (plaintext):**
- `salt` — the password salt (stable across connections)
- `challenge` — random 6-char nonce (changes per connection)

## Step 3A: Pre-Auth SSRF — Internal Port Scanning (Optional)

Before even attempting a password, the attacker can scan the internal network:

```
Attacker sends (plaintext): LoginRequest {
    my_id: "anything",
    password: [all zeros],   // wrong, doesn't matter
    union: PortForward { host: "10.0.0.5", port: 5432 },
}
```

Code execution path:

```
src/server/connection.rs:768-779      — stream.next() → parse protobuf → on_message()
src/server/connection.rs:2100         — if LoginRequest
src/server/connection.rs:2101         — handle_login_request_without_validation()  (NO password check)
src/server/connection.rs:2175         — match PortForward
src/server/connection.rs:2176-2179    — Self::permission(OPTION_ENABLE_TUNNEL, &self.control_permissions)
                                         control_permissions = None → falls through to:
src/server/connection.rs:2009         — Self::is_permission_enabled_locally("enable-tunnel")
                                         access-mode == "full" → returns true
src/server/connection.rs:2192         — TcpStream::connect("10.0.0.5:5432")  ← FIRES BEFORE PASSWORD CHECK
```

**Two outcomes:**
- Port closed → `"Failed to access remote 10.0.0.5:5432"` (line 2200) → return false (line 2205)
- Port open → socket stored (line 2194) → proceeds to password check (line 2293)

**Attacker repeats with different host:port combinations.** No rate limiting applies because the function returns before password validation (line 2205), so `update_failure` is never called.

## Step 3B: Password Brute-Force

The attacker has `salt` from Step 2. For each password guess:

```
Client computes: SHA256(SHA256(guess + salt) + challenge)
Sends: LoginRequest { password: <hash_bytes>, my_id: "attacker", ... }
```

Server validation:

```
src/server/connection.rs:2293        — let (failure, res) = self.check_failure(0).await;
src/server/connection.rs:3436-3459   — Rate limit: 6/minute/IP, 30 total/IP
src/server/connection.rs:2297        — self.validate_password()

src/server/connection.rs:1907-1918   — validate_one_password:
  hasher = SHA256(password + self.hash.salt)
  hasher2 = SHA256(hasher_result + self.hash.challenge)
  hasher2.finalize()[..] == self.lr.password[..]    // ← NON-constant-time comparison
```

**Distributed attack math (1,000 IPs):**
- 6,000 attempts/minute → top 10K passwords in ~2 minutes
- In-memory rate limits (`lazy_static HashMap`) → reset on service restart

**Alternative: Passive eavesdropping.**
Since the channel is unencrypted, capture one legitimate login → have `{salt, challenge, hash}` → offline dictionary attack with no rate limits.

## Step 4: Password Accepted — `send_logon_response`

Password matches:

```
src/server/connection.rs:2309        — self.update_failure(failure, true, 0);  // clear failure counter
src/server/connection.rs:2314        — self.send_logon_response().await;

src/server/connection.rs:1376        — self.authorized = true;       // ← THE GATE OPENS
src/server/connection.rs:1377-1387   — conn_type determined by request type
src/server/connection.rs:1405-1558   — LoginResponse with PeerInfo sent back:
    - username (active user)
    - hostname
    - platform
    - supported features (terminal, privacy mode, etc.)
    - display information
```

**The attacker now has `self.authorized = true`.** All post-auth message handlers become available.

## Step 5: Post-Auth Capabilities — What the Attacker Can Do

With `authorized = true`, the message handler (`on_message`) processes all message types. Here is every capability and its code path:

### 5A: Screen Capture (Remote Desktop)

After auth, the server subscribes the connection to video services:

```
src/server/connection.rs:1637-1654   — sub_service → server.add_connection()
src/server.rs:380-396                — add_connection → subscribes to video_service, audio_service,
                                        clipboard_service, input_service for all monitors
```

Video frames are sent via `tx_video` channel → attacker receives real-time screen content.
**All in plaintext** (no encryption key was set).

### 5B: Keyboard & Mouse Input

```
src/server/connection.rs:2382-2466   — on_message handles message::Union::KeyEvent
src/server/connection.rs:2467-2522   — handles MouseEvent

src/server/connection.rs:1010-1030   — handle_input thread:
    MessageInput::Mouse(mouse_input) → handle_mouse()     // simulates mouse
    MessageInput::Key((msg, press))  → handle_key()        // simulates keypress
```

**Attacker sends keystrokes → executed on target machine.** Can type commands in any open application.

### 5C: Clipboard Access

```
src/server/connection.rs:2547-2600   — handles Cliprdr messages
    → clipboard read/write between attacker and target
```

**Attacker reads clipboard content** (copied passwords, tokens, etc.) and can inject clipboard data.

### 5D: File Transfer

```
src/server/connection.rs:2605-2800   — handles FileAction messages:
    - ReadDir      → list any directory
    - ReadDirAll   → recursive directory listing
    - SendFile     → receive any file from target
    - ReceiveFile  → write any file to target
    - RemoveFile   → delete files
    - RemoveDir    → delete directories
    - CreateDir    → create directories
```

**Full filesystem access** — read any file, write any file, delete any file.
Runs as the service user (root on Linux).

### 5E: Terminal / Shell Access

```
src/server/connection.rs:2127-2174   — LoginRequest with Terminal union
src/server/connection.rs:1659-1662   — self.init_terminal_service().await

src/server/terminal_service.rs:841-882  — PTY creation:
  pty_system.openpty(pty_size)
  cmd = CommandBuilder::new(&shell)      // /bin/bash, /bin/zsh, or /bin/sh
  pty_pair.slave.spawn_command(cmd)      // shell spawned as service user

src/server/connection.rs:3207-3215 (Linux):
  self.terminal_user_token = Some(TerminalUserToken::SelfUser);
  // Parameters IGNORED — always runs as service user
  // If service is root → shell is root
```

**Attacker sends TerminalAction::Data → raw bytes written to PTY → executed as shell commands.**
No command filtering, no sandboxing, no audit (terminal_service.rs:1274-1305).

On Linux with systemd service: **root shell**.
On Windows as service: **SYSTEM shell**.

### 5F: Port Forwarding (Network Pivoting)

```
src/server/connection.rs:2175-2207   — LoginRequest with PortForward
src/server/connection.rs:2192        — TcpStream::connect(host:port) to ANY address
src/server/connection.rs:1109-1163   — try_port_forward_loop:
    forward.next() → self.stream.send_bytes()    // internal → attacker
    self.stream.next() → forward.send()           // attacker → internal
```

**Raw TCP tunnel** to any internal host:port. Combined with root shell, enables:
- Cloud metadata theft (`169.254.169.254`)
- Database access (`10.x.x.x:5432/3306/6379`)
- SSH pivoting (`10.x.x.x:22`)
- Internal web service exploitation

## Step 6: Persistence

With root/SYSTEM shell access, the attacker can:

1. **Create OS-level backdoor** — new user accounts, SSH keys, cron jobs
2. **Modify RustDesk config** — set known password, disable 2FA, redirect RS (via IPC or direct config file edit)
3. **Install additional tools** — C2 implants, keyloggers, miners
4. **Pivot to other machines** — using port forwarding or SSH from the compromised host

## Complete Code Path Diagram

```
INTERNET ATTACKER
       │
       │ TCP connect to 0.0.0.0:21118
       ▼
rendezvous_mediator.rs:802  l.accept()
       │
       │ secure = false, control_permissions = None
       ▼
server.rs:195  create_tcp_connection(secure=FALSE)
       │
       │ Encryption setup SKIPPED (if secure && ... never true)
       ▼
connection.rs:484  on_open(addr)
       │
       │ Hash{salt, challenge} sent in PLAINTEXT
       ▼
connection.rs:1229-1231  self.send(hash)  ──────────────> ATTACKER receives salt+challenge
       │
       │ Wait for message...
       ▼
connection.rs:768-779  stream.next() → on_message()
       │
       ├── PRE-AUTH: LoginRequest with PortForward
       │   │
       │   ▼ connection.rs:2192  TcpStream::connect(attacker_host:attacker_port)
       │   │                     [BEFORE password check]
       │   │
       │   ├── Port closed: "Failed to access remote..."  → return false
       │   └── Port open: store socket → continue to password check
       │
       ├── LoginRequest with password hash
       │   │
       │   ▼ connection.rs:2293  check_failure() [rate limit: 6/min/IP]
       │   │
       │   ▼ connection.rs:2297  validate_password()
       │   │   └── connection.rs:1917  SHA256 compare (non-constant-time)
       │   │
       │   ├── FAIL: "Password wrong" → try again
       │   │
       │   └── SUCCESS:
       │       │
       │       ▼ connection.rs:1376  self.authorized = true
       │       │
       │       ▼ connection.rs:1405  LoginResponse with PeerInfo
       │                             (hostname, username, platform, features)
       │
       ▼ POST-AUTH (authorized = true)
       │
       ├── Screen Capture
       │   server.rs:380  add_connection() → video frames stream
       │
       ├── Keyboard/Mouse
       │   connection.rs:1010-1030  handle_key/handle_mouse → enigo input simulation
       │
       ├── File Transfer
       │   connection.rs:2605-2800  ReadDir/SendFile/ReceiveFile/RemoveFile
       │   (runs as root/SYSTEM)
       │
       ├── Clipboard
       │   connection.rs:2547-2600  read/write clipboard content
       │
       ├── Terminal (ROOT SHELL)
       │   terminal_service.rs:879  spawn_command("/bin/bash")
       │   terminal_service.rs:1294  raw data → PTY (no filtering)
       │   Linux: runs as service user = root
       │   Windows: runs as SYSTEM
       │
       └── Port Forward (NETWORK PIVOT)
           connection.rs:1132-1146  bidirectional TCP proxy
           to ANY internal host:port
           ├── 169.254.169.254:80   → cloud credentials
           ├── 10.0.0.x:5432       → PostgreSQL
           ├── 10.0.0.x:22         → SSH
           └── 127.0.0.1:*         → localhost services
```

## Severity Assessment

| Step | Severity | Issue |
|---|---|---|
| Port 21118 open to internet | CRITICAL | `listen_any(port)` binds to 0.0.0.0 by default |
| No encryption on direct port | CRITICAL | `secure=false` hardcoded at call site |
| Pre-auth SSRF | HIGH | `TcpStream::connect` before password validation |
| Weak rate limiting | HIGH | Per-IP, in-memory, 6/min with 30 total |
| Non-constant-time password compare | MEDIUM | `==` operator on hash slices |
| Root/SYSTEM terminal | CRITICAL | No privilege drop, no command filtering |
| Unrestricted port forwarding | HIGH | Any host:port after auth |
| No encryption on session data | CRITICAL | Screen, keyboard, files all in plaintext |

## What Makes This a Complete Kill Chain

Every step has been traced through actual code paths. However, an honest assessment of what an attacker can actually achieve requires distinguishing what is **realistic** from what is **theoretical**.

---

# Part V: Honest Practical Assessment — What Actually Works

## Critical Correction: Direct Server Is OFF by Default

The `option2bool` function (`flutter/lib/common.dart:1572-1580`) treats `"direct-server"` as opt-in:

```dart
} else if (option == kOptionDirectServer || ...) {
    res = value == "Y";    // Must be EXPLICIT "Y" to enable
}
```

**Port 21118 does not listen unless the user manually enables "Enable direct IP access."**

Furthermore, the normal connection flow (via rendezvous server) passes `secure: true`:

| Connection Path | `secure` | Encryption | Code |
|---|---|---|---|
| Direct server (port 21118) | `false` | **NEVER** | `rendezvous_mediator.rs:815` |
| Hole-punch via RS | `true` | **YES** | `rendezvous_mediator.rs:560,643` |
| Relay via RS | variable | Usually yes | `rendezvous_mediator.rs:476` |

The normal connection path IS encrypted. This means the Part IV kill chain (internet → root shell) requires a **non-default configuration**.

## Realistic Threat Matrix by Access Level

### Tier 1: Pure Internet Attacker — No Access at All

**Scenario A: Target has default configuration (direct server OFF)**

| Attack | Works? | Why |
|---|---|---|
| Port scan for 21118 | **NO** | Port not listening (disabled by default) |
| Pre-auth SSRF | **NO** | No direct port to connect to |
| Password brute-force over direct port | **NO** | No direct port to connect to |
| Eavesdrop on password hash | **NO** | Normal RS path uses encryption |
| Connect via RS + brute-force password | **YES, but slow** | Must go through RS, connection is encrypted, but password guessing still possible at 6/min/IP |
| Protocol downgrade on RS connection | **NO** | Requires MITM position on network path |
| Compromised public RS → MITM | **YES** | If attacker compromises the RS infrastructure itself (Finding 13, Chain G) |

**Realistic outcome with default config:** An internet attacker can only brute-force the password through the rendezvous server at 6 attempts/minute/IP. With a strong password (12+ chars), this is **infeasible**. With a weak password (common dictionary word), it could succeed in days with distributed IPs.

**Scenario B: Target has direct server enabled + port reachable (non-default)**

| Attack | Works? | Why |
|---|---|---|
| Port scan for 21118 | **YES** | Port listening on 0.0.0.0 |
| Pre-auth SSRF/port scan | **YES** | Finding 16 — TcpStream::connect before auth |
| Password brute-force | **YES** | Unencrypted channel, 6/min/IP |
| Passive eavesdrop → offline crack | **YES** | No encryption on direct port |
| Root shell after password crack | **YES** | Full Part IV chain |

**Realistic outcome:** Full kill chain works, but requires BOTH direct server enabled AND port reachable from internet (not behind NAT). This is a **real configuration** in:
- Cloud VMs with public IPs (no firewall rules on 21118)
- Corporate networks where direct access is enabled for IT convenience
- IoT/kiosk deployments with static public IPs
- Self-hosted servers exposed to the internet

### Tier 2: LAN Attacker — Same Network, No Credentials

| Attack | Works? | Requires |
|---|---|---|
| LAN discovery → enumerate devices | **YES** | Nothing — default ON, no auth (Finding 17) |
| Receive device ID, hostname, username, MAC | **YES** | Single UDP packet to port 21119 |
| ARP spoof → MITM RS connection | **YES** | ARP spoofing capability |
| Strip PK from PunchHoleResponse → downgrade | **YES** | MITM position (via ARP spoof) |
| Unencrypted session → eavesdrop passwords | **YES** | Combined with protocol downgrade |
| Direct port (if enabled) → unencrypted brute-force | **YES** | Direct server enabled |

**Realistic outcome:** A LAN attacker can enumerate targets via LAN discovery (always works), and if they can ARP spoof, they can downgrade the encryption on any rendezvous-mediated connection. This is the most practical remote attack scenario.

### Tier 3: Local Unprivileged User — Shell Access on Target Machine

| Attack | Works? | Requires |
|---|---|---|
| Read permanent password via IPC | **YES** | Any local user (IPC is 0o0777) |
| Read 2FA secret via IPC + decrypt with "00" | **YES** | Any local user |
| Replace entire config via SyncConfig | **YES** | Any local user |
| Redirect to rogue RS → MITM all connections | **YES** | Any local user |
| Remote access from anywhere with stolen creds | **YES** | Any local user |
| Persistent backdoor surviving password changes | **YES** | Any local user |

**Realistic outcome:** This is the most dangerous tier. **Any unprivileged local user on the machine has complete control.** No brute-force needed, no network position needed, no configuration requirements. The IPC socket permissions (0o0777) make this unconditional. This is the chain that works 100% of the time on any RustDesk installation.

## The Complete Picture

```
ACCESS LEVEL          WHAT ACTUALLY WORKS                    REAL-WORLD LIKELIHOOD
─────────────────────────────────────────────────────────────────────────────────

Internet only         Password brute-force via RS            LOW (encrypted, rate-limited,
(default config)      (only path available)                  strong passwords survive)

Internet only         Full Part IV kill chain:               MEDIUM in specific environments
(direct server ON     unencrypted, SSRF, brute-force,       (cloud VMs, corporate IT,
+ port reachable)     root shell                            kiosks, self-hosted)

Same LAN              LAN discovery + ARP spoof +            HIGH (LAN access is common,
                      protocol downgrade → plaintext         ARP spoofing is trivial,
                      session interception                   discovery always works)

Local unprivileged    IPC → read all creds → remote          CERTAIN (works on 100% of
user                  access from anywhere → root shell      installations, no conditions)
```

## What the Original Claim Should Have Said

**Original (incorrect):**
> "The only thing between an internet attacker and a root shell on port 21118 is the user's password — transmitted over an unencrypted channel with bypassable rate limiting."

**Corrected:**
> Port 21118 is off by default. When the user enables it AND the port is internet-reachable, the connection is unencrypted with bypassable rate limiting. With default configuration, remote attacks must go through the rendezvous server where encryption is active — the password is the barrier, but it's properly protected in transit. The unconditional vulnerability is at the local level: any unprivileged user on the machine can read all credentials via the world-accessible IPC socket and gain full remote access from anywhere without any brute-force.

## Findings Severity Re-Assessment

| Finding | Original Severity | Revised Severity | Rationale |
|---|---|---|---|
| IPC socket 0o0777 (F1) | CRITICAL | **CRITICAL** — unchanged | Works on 100% of installations, no prerequisites |
| 2FA hardcoded key (F3) | HIGH-CRITICAL | **HIGH-CRITICAL** — unchanged | Unconditional via IPC |
| Protocol downgrade (F13) | CRITICAL | **HIGH** | Requires MITM position (ARP spoof or network control) |
| SyncConfig full replace (F14) | CRITICAL | **CRITICAL** — unchanged | Unconditional via IPC |
| Direct port unencrypted (F15) | CRITICAL | **HIGH** | Direct server is off by default |
| Pre-auth SSRF (F16) | HIGH | **HIGH (conditional)** | Only when direct server is enabled |
| LAN discovery info leak (F17) | MEDIUM | **MEDIUM** — unchanged | LAN-only, but always on by default |
| Distributed brute-force (F18) | HIGH | **MEDIUM-HIGH** | Direct port is off by default; RS path is encrypted |

## The Three Real Threats (in order of practical danger)

**1. Any local user → full remote compromise (CERTAIN)**
IPC socket permissions are hardcoded. Cannot be mitigated without code changes. Works on every installation.

**2. LAN attacker → protocol downgrade → session interception (HIGH)**
LAN discovery is on by default, ARP spoofing is trivial. Requires same-network position but no credentials.

**3. Direct-port internet attack → root shell (CONDITIONAL)**
Requires non-default configuration (direct server enabled) AND network reachability. When conditions are met, the kill chain is devastating. But conditions are not met by default.

---

# Part VI: Random ID Scanning via Rendezvous Server — Pure Remote Attack (Default Config)

## The Question

Can an attacker with zero prior access randomly scan RustDesk device IDs through the public rendezvous server, find online devices, and gain access — all against DEFAULT configuration?

## FINDING 19 (HIGH): Device ID Enumeration Oracle via Rendezvous Server

**File:** `src/client.rs:483-502`
**Impact:** Attacker can enumerate all valid RustDesk device IDs through the public RS
**Type:** CWE-204 (Observable Response Discrepancy)

### Device ID Format

RustDesk device IDs are **9-digit numeric** values (e.g., "123 456 789"):

```dart
// flutter/lib/common/formatter/id_formatter.dart:43
if (int.tryParse(id2) == null) return id;  // Numeric only
```

**Total keyspace: 10^9 = 1,000,000,000 (1 billion)**

IDs are derived from a UUID/machine-UID hash, not sequential — but the keyspace is only 9 digits.

### The Enumeration Oracle

When a client sends a `PunchHoleRequest` to the rendezvous server, the RS returns distinct error codes:

```rust
// src/client.rs:488-501
match ph.failure.enum_value() {
    Ok(punch_hole_response::Failure::ID_NOT_EXIST) => {
        bail!("ID does not exist");           // ID never registered
    }
    Ok(punch_hole_response::Failure::OFFLINE) => {
        bail!("Remote desktop is offline");   // ID exists, device not connected
    }
    // ... LICENSE_MISMATCH, LICENSE_OVERUSE
}
```

| RS Response | Meaning | What Attacker Learns |
|---|---|---|
| `ID_NOT_EXIST` | Never registered | This ID is invalid — skip it |
| `OFFLINE` | Registered but not connected | **This ID is REAL** — device exists, try later |
| Success (socket_addr) | Registered and online | **This ID is LIVE** — can attempt connection now |

**This is a binary oracle.** The attacker sends random 9-digit IDs and instantly knows which ones are real registered devices.

### Scanning Speed Calculation

An attacker writes a custom client that sends `PunchHoleRequest` messages directly to the public RS:

```
Assumptions:
- Public RS accepts connections from any client (it must, for the protocol to work)
- RS probably has some rate limiting, but even at 100 requests/second/connection:
- With 10 parallel connections: ~1,000 IDs/second
- Estimated registered devices: ~1-10 million out of 1 billion possible IDs

Finding registered devices:
- Hit rate: 0.1% to 1%
- Average probes to find one registered device: 100-1,000
- Time: 0.1 to 10 seconds per discovered device
- At 1,000 IDs/second: discover ~1-10 registered devices per second

Finding ONLINE devices:
- Of registered devices, maybe 10-50% are online at any time
- Every ~2-10 registered devices found → 1 online device
- Net rate: ~0.1-5 online devices discovered per second
```

**Result: An attacker can build a list of thousands of online RustDesk devices per hour just by probing the public RS.**

## Attack Chain: Random ID Scan → Password Attack → Access

### Phase 1: Mass ID Enumeration (hours)

```
Attacker's custom client → Public RS:
├─ Send PunchHoleRequest(id="100000000") → ID_NOT_EXIST
├─ Send PunchHoleRequest(id="100000001") → ID_NOT_EXIST
├─ ...
├─ Send PunchHoleRequest(id="238471956") → OFFLINE ← REGISTERED!
├─ ...
├─ Send PunchHoleRequest(id="519283746") → SUCCESS ← ONLINE NOW!
└─ Store all discovered IDs with status

Output: List of thousands of valid device IDs + their online status
```

### Phase 2: Target Selection

From the discovered IDs, attacker can:
1. Probe each online ID → receive `LoginResponse` with PeerInfo containing:
   - `username` — logged-in user (`connection.rs:1404`)
   - `hostname` — machine name (`connection.rs:1414`)
   - `platform` — OS type (`connection.rs:1415`)

Wait — does PeerInfo leak BEFORE password auth? Let me verify:

```
The flow is:
1. PunchHoleRequest → RS → PunchHoleResponse (get peer address)
2. TCP connect to peer (via hole-punch or relay)
3. Key exchange (secure=true, encrypted)
4. Receive Hash{salt, challenge}              ← BEFORE auth
5. Send LoginRequest{password}
6. IF password correct → receive LoginResponse with PeerInfo
7. IF password wrong → receive error
```

**PeerInfo (hostname, username, platform) is ONLY sent after successful password verification.** So the attacker cannot harvest hostnames without cracking the password first.

However, **the salt IS leaked** to any connecting client (step 4). The salt is stable across connections (`Config::get_salt()` at `connection.rs:364`). This enables:
- Precomputation of password hashes for common passwords
- Same salt used for all connections from all attackers → rainbow table viable

### Phase 3: Password Brute-Force Against Discovered Online Devices

Through the RS-mediated encrypted connection:

```
Per-device rate limits (connection.rs:3436-3459):
├─ 6 attempts per minute per IP
├─ 30 total attempts per IP (lifetime until success/restart)
├─ In-memory only → resets on service restart
└─ IPv6: 60/64-prefix, 80/56-prefix, 100/48-prefix

Distributed attack:
├─ 1,000 IPs × 6 attempts/min = 6,000 attempts/minute per target
├─ Before hitting lifetime limit: 30,000 attempts (30 per IP × 1,000 IPs)
├─ Then rotate to fresh IPs
```

**Against different password types:**

| Password Type | Keyspace | Time @ 6,000/min | Feasible? |
|---|---|---|---|
| Default temporary (6 alphanumeric) | ~2.2 billion (36^6) | ~250 days | **NO** |
| Default temporary (8 chars) | ~2.8 trillion | ~880 years | **NO** |
| Weak permanent ("123456") | Top 10,000 | **< 2 minutes** | **YES** |
| Common password (dictionary) | ~1 million | **~3 hours** | **YES** |
| Moderate password (8 char common) | ~10 million | **~28 hours** | **YES** |
| Strong password (12+ random) | >10^18 | Never | **NO** |

### Phase 4: Access After Password Crack

After successful authentication (through encrypted RS-mediated connection):
- Connection IS encrypted (secure=true)
- Full access: screen, keyboard, files, clipboard
- Terminal access (root shell if service runs as root) — `terminal_service.rs:879`
- Port forwarding to internal network — `connection.rs:1132-1146`

## What Actually Blocks This Chain

| Barrier | Strength | Bypass |
|---|---|---|
| ID is 9 digits (1B keyspace) | WEAK | Enumeration oracle makes scanning trivial |
| RS may rate-limit PunchHoleRequests | UNKNOWN | RS code not in this repo; likely some rate limiting exists |
| Connection is encrypted (secure=true) | STRONG | Cannot eavesdrop password; must online brute-force |
| Password rate limit (6/min/IP) | MODERATE | Distributed IPs bypass; in-memory resets on restart |
| Default temporary password | STRONG | Keyspace too large for rate-limited brute-force |
| User-set permanent password | **VARIABLE** | Weak passwords crackable; strong passwords survive |

## Honest Assessment

**Can an attacker scan random IDs and gain access? YES — but only against weak passwords.**

The complete chain:

```
Step 1: Scan IDs via public RS            → WORKS (enumeration oracle, ~seconds per device found)
Step 2: Connect to online device via RS   → WORKS (normal protocol, encrypted)
Step 3: Receive Hash{salt, challenge}     → WORKS (pre-auth, salt is stable)
Step 4: Brute-force password              → DEPENDS ON PASSWORD STRENGTH
Step 5: Full access (screen/shell/files)  → WORKS after auth
```

**The default temporary password (random alphanumeric, 6-8 chars) makes brute-force infeasible** at 6,000 attempts/minute. This is the primary defense.

**But many real users:**
- Set weak permanent passwords ("123456", "password", company name, etc.)
- Disable the temporary password and rely only on permanent password
- Use short numeric passwords for convenience

Against these users, the random-scan attack chain is **fully viable from the internet with zero prior access**.

## FINDING 20 (MEDIUM): Stable Salt Enables Password Hash Precomputation

**File:** `src/server/connection.rs:364`
**Type:** CWE-916 (Use of Password Hash with Insufficient Computational Effort)

The salt used in the password challenge-response is **stable** (loaded from config, same for all connections):

```rust
let hash = Hash {
    salt: Config::get_salt(),               // Same for every connection
    challenge: Config::get_auto_password(6), // Random per connection
    ..Default::default()
};
```

The password verification is: `SHA256(SHA256(password + salt) + challenge)`

Since `salt` is stable and sent to the client before auth, an attacker can:
1. Connect once → receive `salt`
2. Precompute `SHA256(password + salt)` for millions of common passwords (offline, no rate limit)
3. For each new connection, only compute the final `SHA256(precomputed + challenge)` — which is trivial
4. This effectively reduces the per-connection work to one SHA256 per password guess

Combined with the ID enumeration oracle, this enables **mass-scale automated password attacks** against all discovered online devices.

---

## Updated Threat Summary

```
ATTACK SCENARIO                         WORKS?     CONDITIONS
──────────────────────────────────────────────────────────────────────

Random ID scan → find devices           YES        Just need RS access (public)
ID enumeration → build target list      YES        RS distinguishes ID_NOT_EXIST vs OFFLINE
Connect to online device → encrypted    YES        Normal RS flow, encrypted
Brute-force default temp password       NO         Keyspace too large (36^6+)
Brute-force weak permanent password     YES        Common passwords crack in minutes-hours
Mass scan → auto-crack weak passwords   YES        Combine ID scan + precomputed salt hashes
  across thousands of devices
Access after password crack             YES        Root shell, files, screen, network pivot

BOTTOM LINE:
- Against users with STRONG passwords: attack FAILS at password step
- Against users with WEAK passwords: attack SUCCEEDS end-to-end
- The ID enumeration oracle makes targeting trivial
- The stable salt enables precomputation
- NO local access, NO network adjacency, NO special config needed
- Works against DEFAULT configuration through the PUBLIC rendezvous server
```

---

# Part VII: Novel Unauthenticated Access Chains — Beyond Password Cracking

## Methodology

Parts I-VI focused on password-centric attacks. This section presents **novel attack chains that bypass authentication entirely** — no password cracking, no brute-force. These chains exploit protocol design flaws, pre-auth message processing gaps, trust chain weaknesses, and cross-connection state confusion to achieve unauthorized access through chaining multiple vulnerabilities.

## Pre-Authentication Attack Surface Map

The `on_message` handler (`src/server/connection.rs:2089`) processes these message types **BEFORE** `self.authorized` is set to `true`:

| Message Type | Line | Auth Check | Side Effect |
|---|---|---|---|
| `Misc::CloseReason` | 2092 | NONE | Closes connection, removes session from global SESSIONS |
| `LoginRequest::FileTransfer` | 2106 | NONE | Sets `self.file_transfer` flag (pre-auth mode selection) |
| `LoginRequest::ViewCamera` | 2118 | NONE | Sets `self.view_camera = true` |
| `LoginRequest::Terminal` | 2127 | NONE | Sets `self.terminal = true`, processes OS credentials |
| `LoginRequest::PortForward` | 2175 | NONE | **`TcpStream::connect()` to arbitrary host:port** |
| `Auth2fa` | 2321 | Partial (2FA code only) | Can grant full auth, stores trusted device |
| `TestDelay` | 2354 | NONE | Reflects messages, writes global VIDEO_QOS state |
| `SwitchSidesResponse` | 2370 | NONE | **UUID match → `authorized = true` WITHOUT password** |

**Password validation happens ONLY at line 2297** — everything above executes before it.

**Authorization (`self.authorized = true`) is set ONLY at line 1376** in `send_logon_response()`, reachable via:
1. Line 2278: `is_recent_session(false)` (session reuse — still needs password hash)
2. Line 2314: After `validate_password()` succeeds
3. Line 2332: After 2FA validation succeeds
4. **Line 2383: After `SwitchSidesResponse` UUID match — NO PASSWORD CHECK**

## FINDING 21 (CRITICAL): SwitchSides IPC → Complete Authentication Bypass

**Files:** `src/ipc.rs:738-745`, `src/server/connection.rs:2370-2394`, `src/server/connection.rs:4710-4715`
**Impact:** Any local user gains full RustDesk access WITHOUT password or 2FA
**Type:** CWE-288 (Authentication Bypass Using an Alternate Path)

### The SwitchSides Mechanism (Normal Flow)

"Switch Sides" lets an authenticated client swap roles with the server — the server becomes the client and vice versa. Normal flow:

```
1. Client A (authenticated on Server B) calls switch_sides()
2. A's IPC handler generates UUID v4, stores in SWITCH_SIDES_UUID[A_id]
3. A sends Misc::SwitchSidesRequest(uuid) to B over network
4. B receives request (POST-AUTH handler, line 3085)
5. B runs: run_me(["--connect", A_id, "--switch_uuid", uuid])
6. B's new process connects to A's server
7. B sends SwitchSidesResponse(uuid, login_request)
8. A's server matches UUID → authorized WITHOUT password
```

### The Exploit: IPC Socket → UUID Theft → Auth Bypass

The IPC socket is world-accessible (`0o0777` on Unix, `SecurityAttributes::allow_everyone_create()` on Windows). **Any local user** can:

```
Step 1: Connect to IPC socket (no authentication required)
        └─ ipc.rs:442  → permissions 0o0777
        └─ ipc.rs:433  → allow_everyone_create() on Windows

Step 2: Send Data::SwitchSidesRequest("attacker_fake_id")
        └─ ipc.rs:738  → handler receives the request

Step 3: IPC generates UUID v4 and stores it
        └─ ipc.rs:739  → let uuid = uuid::Uuid::new_v4();
        └─ ipc.rs:740  → insert_switch_sides_uuid("attacker_fake_id", uuid)
        └─ connection.rs:4710-4714 → SWITCH_SIDES_UUID["attacker_fake_id"] = (now, uuid)

Step 4: IPC returns UUID to the attacker
        └─ ipc.rs:743  → stream.send(&Data::SwitchSidesRequest(uuid.to_string()))
        └─ Attacker now KNOWS the UUID

Step 5: Attacker opens TCP connection to RustDesk server
        └─ Can be localhost, or via RS-mediated connection
        └─ Server sends Hash{salt, challenge} in on_open (line 1216)

Step 6: Attacker SKIPS LoginRequest entirely
        └─ Sends SwitchSidesResponse message directly:
        └─ uuid: the UUID from Step 4
        └─ lr.my_id: "attacker_fake_id" (matches SWITCH_SIDES_UUID key)

Step 7: Server processes SwitchSidesResponse (PRE-AUTH, line 2370)
        └─ connection.rs:2377 → cleans entries older than 10 seconds
        └─ connection.rs:2378 → removes "attacker_fake_id" from SWITCH_SIDES_UUID
        └─ connection.rs:2381 → uuid == uuid_old → MATCH!
        └─ connection.rs:2382 → self.from_switch = true
        └─ connection.rs:2383 → self.send_logon_response().await

Step 8: send_logon_response() grants full access
        └─ connection.rs:1345 → self.require_2fa.is_some() && !self.from_switch
        └─ from_switch = true → 2FA CHECK COMPLETELY SKIPPED
        └─ connection.rs:1376 → self.authorized = true
        └─ FULL ACCESS: screen, keyboard, files, terminal (root shell), port forwarding
```

### Why This Is Critical

- **No password needed** — the UUID is the only "credential" and it's obtained from IPC
- **No 2FA needed** — `from_switch = true` explicitly bypasses the 2FA check (line 1345)
- **Any local user** — the IPC socket is world-accessible
- **No timing window** — attacker controls both the UUID request and the connection timing
- **Works on all platforms** — Unix (0o0777) and Windows (allow_everyone_create)
- **Default configuration** — no special settings required

### The 10-Second Race Window

The UUID entry is cleaned up after 10 seconds (line 2377). But since the attacker controls both steps (IPC request and TCP connection), they can execute both within milliseconds. There is no real race condition — the attacker has complete control of timing.

## FINDING 22 (CRITICAL): IPC RS Public Key Injection → Full Trust Chain Takeover

**Files:** `src/ipc.rs:690-703`, `src/common.rs` (`get_rs_pk`, `decode_id_pk`)
**Impact:** Attacker replaces RS public key via IPC → controls all future connection trust
**Type:** CWE-295 (Improper Certificate Validation) / CWE-345 (Insufficient Verification of Data Authenticity)

### The Attack Chain

The Rendezvous Server (RS) is the **sole root of trust** in RustDesk. It signs `{ID, PublicKey}` pairs that clients use to verify peer identity. The RS public key determines what signatures are trusted.

```
Step 1: Attacker connects to world-accessible IPC socket

Step 2: Send Data::Options with "key" → attacker_public_key_base64
        └─ ipc.rs:690-703 → Config::set_option("key", attacker_key)
        └─ No authentication, no validation, immediate effect

Step 3: Send Data::Options with "rendezvous-servers" → "attacker.evil.com"
        └─ Redirects all RS communication to attacker-controlled server
        └─ Application will reconnect to new RS

Step 4: Attacker's rogue RS signs arbitrary {ID, PublicKey} pairs
        └─ common.rs:decode_id_pk verifies against the "key" config option
        └─ Since "key" is now attacker's key → signatures verify correctly

Step 5: All future connections trust attacker's signatures
        └─ Client connects to peer → asks RS for peer's signed PK
        └─ Attacker's RS returns {peer_id, attacker_pk} signed with attacker's key
        └─ Client verifies signature → succeeds (key replaced in Step 2)
        └─ DH key exchange uses attacker's PK → attacker has shared secret
        └─ FULL MITM: attacker decrypts, modifies, re-encrypts all traffic

Result: Every future remote connection is transparently intercepted
```

### Chaining: IPC RS Override → Remote Access to ALL Peers

1. **Local attacker** replaces RS key and server via IPC (Finding 22)
2. **Target device** now connects to attacker's rogue RS
3. Any peer connecting TO this device → attacker controls key exchange → MITM
4. Any connection FROM this device → attacker controls relay selection → MITM
5. Through MITM, attacker captures passwords, session tokens, file transfers
6. Attacker uses captured credentials to access other devices
7. **Lateral movement**: one local IPC access → access to entire fleet

## FINDING 23 (HIGH): Protocol Downgrade → SwitchSides UUID Theft → Remote Auth Bypass

**Files:** `src/client.rs:781-816`, `src/server/connection.rs:2370-2394`, `src/server/connection.rs:3085-3097`
**Impact:** Network attacker hijacks switch-sides operation for passwordless access
**Type:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)

### The Attack Chain

When two peers use "Switch Sides" and an attacker has network MITM position:

```
SETUP: Client A ←──MITM──→ Server B (encrypted connection)

Step 1: MITM forces protocol downgrade on NEXT connection
        └─ When B starts new process to connect back to A,
            MITM intercepts the RS PunchHoleResponse
        └─ Returns empty signed_id_pk → client.rs:781-787
        └─ B's new process falls back to unencrypted

Step 2: A sends SwitchSidesRequest(uuid) to B over EXISTING connection
        └─ connection.rs:3085 (POST-AUTH handler)
        └─ If existing connection was also downgraded, UUID visible in plaintext

Step 3: B starts: run_me(["--connect", A_id, "--switch_uuid", uuid])
        └─ B's new process connects to A
        └─ All traffic visible to MITM (no encryption due to downgrade)

Step 4: MITM captures UUID from B's SwitchSidesResponse

Step 5: MITM RACES B's process — connects to A's server FIRST
        └─ Sends SwitchSidesResponse with stolen UUID
        └─ UUID is consumed (remove from HashMap) — one-time use

Step 6: A's server validates UUID → authorized
        └─ connection.rs:2381-2383 → from_switch = true → full access
        └─ MITM is now authorized on A without any password

Step 7: B's legitimate process fails
        └─ UUID already consumed → no match → connection rejected
```

### Real-World Trigger

Switch Sides is triggered by user action in the Flutter UI (`flutter_ffi.rs:900`). An attacker with persistent MITM position (e.g., ARP spoofing on LAN, compromised router) waits for a Switch Sides event, then executes the race.

## FINDING 24 (HIGH): Pre-Auth SSRF → Internal Network Reconnaissance

**Files:** `src/server/connection.rs:2175-2207`
**Impact:** Unauthenticated attacker scans internal network through target device
**Type:** CWE-918 (Server-Side Request Forgery)

### Validated Pre-Auth TCP Connect

```rust
// connection.rs:2190-2206 — INSIDE LoginRequest handler, BEFORE password check
let mut addr = format!("{}:{}", pf.host, pf.port);  // Attacker-controlled
self.port_forward_address = addr.clone();
match timeout(3000, TcpStream::connect(&addr)).await {  // FIRES PRE-AUTH
    Ok(Ok(sock)) => {
        self.port_forward_socket = Some(Framed::new(sock, BytesCodec::new()));
        // Socket stored — connection established to internal target
    }
    _ => {
        self.send_login_error(format!(
            "Failed to access remote {}, please make sure if it is open",
            addr    // INFORMATION DISCLOSURE: reveals port status
        )).await;
        return false;
    }
}
```

### Exploitation

```
Step 1: Connect to target RustDesk device (via RS, default config)

Step 2: Send LoginRequest with PortForward variant:
        host: "192.168.1.1"    ← attacker-controlled
        port: 22               ← attacker-controlled

Step 3: Server makes TCP connection to 192.168.1.1:22 BEFORE checking password
        └─ Success: no error sent, port_forward_socket stored
        └─ Failure: error message "Failed to access remote 192.168.1.1:22"

Step 4: Attacker learns:
        └─ Port open → no immediate error (connection stays alive)
        └─ Port closed → specific error message returned
        └─ Host unreachable → different error/timeout behavior

Step 5: Repeat with different hosts and ports
        └─ NO login timeout on unauthenticated connections (Finding 25)
        └─ NO rate limiting on LoginRequest submissions
        └─ Map entire internal network: hosts, ports, services

Step 6: Special targets:
        └─ "RDP" + port 0 → auto-expanded to localhost:3389 (line 2182-2185)
        └─ localhost:* → scan all services on the target machine
        └─ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 → scan internal ranges
```

## FINDING 25 (MEDIUM): No Login Timeout → Indefinite Pre-Auth Resource Hold

**File:** `src/server/connection.rs:465, 907-917, 1721`
**Impact:** Unauthenticated connections persist indefinitely, enabling sustained attacks
**Type:** CWE-400 (Uncontrolled Resource Consumption)

### The Gap

```rust
// Line 465 (Connection::new):
auto_disconnect_timer: None,  // ← Starts as None

// Line 1721 (send_logon_response — POST-AUTH ONLY):
self.auto_disconnect_timer = Self::get_auto_disconenct_timer();  // ← Only set AFTER auth

// Line 907-917 (main loop timer):
if let Some((instant, minute)) = conn.auto_disconnect_timer.as_ref() {
    // Only fires if timer exists — which is NEVER for unauthed connections
}
```

**No mechanism disconnects unauthenticated connections.** Combined with:
- Pre-auth SSRF (Finding 24): each connection holds an internal TCP socket open
- Pre-auth TestDelay reflection (line 2354): keepalive without authentication
- No connection limit: unlimited unauthenticated connections simultaneously

An attacker can exhaust file descriptors and memory by opening thousands of unauthenticated connections, each holding an internal SSRF socket.

## FINDING 26 (HIGH): Relay Connection Token Race → Session Hijack

**Files:** `src/client.rs:860-920`, `src/rendezvous_mediator.rs:413-452`
**Impact:** Attacker hijacks relay pairing to intercept/inject traffic
**Type:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

### Relay Token Mechanism

Relay connections use UUID v4 tokens to match two peers at the relay server. The token flows:
1. Client generates UUID → sends to RS in `RelayResponse`
2. RS forwards UUID to relay server in `RequestRelay`
3. Peer also sends `RequestRelay` with same UUID
4. Relay server pairs connections by UUID match

### The Race

```
Step 1: Attacker monitors RS communication (network MITM or rogue RS)
Step 2: Observes RelayResponse containing UUID from legitimate client
Step 3: Attacker sends RequestRelay(uuid) to relay server BEFORE the peer
Step 4: Relay server pairs attacker with the legitimate client
Step 5: Legitimate peer's RequestRelay arrives → UUID already consumed
Step 6: Attacker sits between client and server:
        ├─ Decrypts if protocol was downgraded
        ├─ Sees all screen data, keystrokes, file transfers
        └─ Can inject commands in real-time
```

### Critical Weakness

- Relay server performs **no authentication** — just UUID matching
- No cryptographic binding between UUID and peer identity
- No verification that RequestRelay came from the expected peer
- Attack requires network MITM position OR rogue RS (chainable with Finding 22)

## FINDING 27 (MEDIUM): Trusted Device Persistence → Permanent 2FA Bypass

**File:** `src/server/connection.rs:2338-2345`
**Impact:** One-time 2FA code → permanent future 2FA bypass
**Type:** CWE-613 (Insufficient Session Expiration) / CWE-308 (Use of Single-factor Authentication)

### Trusted Device Storage

When a user successfully completes 2FA, the Auth2fa handler stores a "trusted device":

```rust
// connection.rs:2338-2345 — POST-AUTH, inside Auth2fa handler
Config::add_trusted_device(TrustedDevice {
    hwid: tfa.hwid,           // ← CLIENT-PROVIDED
    time: hbb_common::get_time(),
    id: self.lr.my_id.clone(),      // ← CLIENT-PROVIDED
    name: self.lr.my_name.clone(),  // ← CLIENT-PROVIDED
    platform: self.lr.my_platform.clone(), // ← CLIENT-PROVIDED
});
```

### The Attack

```
Step 1: Attacker obtains ONE valid 2FA code
        └─ Social engineering, telegram bot compromise, phishing
        └─ Temporary: code is only valid for 30 seconds

Step 2: Authenticate with password + 2FA code
        └─ Include crafted hwid in Auth2fa message: hwid="ATTACKER_PERSISTENT_ID"

Step 3: Trusted device record persisted to Config (disk)
        └─ {hwid: "ATTACKER_PERSISTENT_ID", id: "attacker_id", name: "attacker", platform: "Windows"}

Step 4: All future connections — 2FA bypassed permanently
        └─ handle_login_request_without_validation (line 2039-2050):
        └─ Matches hwid + id + name + platform → self.require_2fa = None
        └─ Only need password — 2FA never prompted again

Step 5: Even if 2FA secret is rotated, trusted device persists
        └─ Only cleared by explicit Data::ClearTrustedDevices IPC command
```

## FINDING 28 (MEDIUM): Cross-Connection LOGIN_FAILURES Poisoning → Targeted Lockout

**File:** `src/server/connection.rs:70, 3412-3461`
**Impact:** Attacker locks out legitimate users by poisoning shared rate-limiting state
**Type:** CWE-770 (Allocation of Resources Without Limits or Throttling)

### The Vulnerability

```rust
// Line 70: Global mutable state shared across ALL connections
static ref LOGIN_FAILURES: Arc<Mutex<HashMap<String, (i32, i32, i32)>>> = Default::default();
```

Rate limiting uses IP-based tracking. An attacker can:
1. Send 6 failed login attempts from a target IP (or shared NAT IP)
2. Legitimate user on same IP is now locked out for that minute
3. Send 30 total attempts → permanent lockout (until service restart)
4. In-memory state → resets on restart, but attacker can repeat

In shared network environments (corporate NAT, WiFi hotspots, VPN exit nodes), an attacker behind the same IP can deny service to all other users on that IP.

---

## Complete Novel Attack Chains Summary

### Chain I: Local → Full Access (No Password, No 2FA)
```
IPC socket (0o0777) → SwitchSidesRequest → Get UUID →
TCP connect → SwitchSidesResponse(uuid) → authorized = true
Findings: 21 (SwitchSides bypass)
Impact: CRITICAL — any local user → root shell
```

### Chain J: Local → Persistent MITM of All Connections
```
IPC socket → Set "key" to attacker PK → Set "rendezvous-servers" to attacker RS →
Rogue RS signs arbitrary {ID, PK} pairs → MITM all future connections →
Capture passwords → Access all connected peers
Findings: 22 (RS PK injection) + 5 (IPC world-accessible)
Impact: CRITICAL — one local access → control entire device fleet
```

### Chain K: Network MITM → Passwordless Access via SwitchSides Theft
```
Force protocol downgrade → Observe SwitchSidesRequest(uuid) in plaintext →
Race legitimate connection → SwitchSidesResponse(stolen_uuid) → authorized
Findings: 23 (UUID theft) + 13 (protocol downgrade)
Impact: HIGH — network position → full access without credentials
```

### Chain L: Remote → Internal Network Mapping (Default Config)
```
RS-mediated connection → LoginRequest::PortForward(internal_host:port) →
Server TcpStream::connect() BEFORE auth → Error/success reveals port status →
No login timeout → scan indefinitely → map entire internal network
Findings: 24 (pre-auth SSRF) + 25 (no login timeout)
Impact: HIGH — zero credentials → full internal network reconnaissance
```

### Chain M: Relay Token Race → Traffic Interception
```
Network MITM → Observe relay UUID → Race to relay server →
Hijack pairing → Sit between client and server → See/modify all traffic
Findings: 26 (relay race) + 13 (protocol downgrade)
Impact: HIGH — intercept all data in relay connections
```

### Chain N: One-Time 2FA → Permanent Bypass
```
Social engineer one 2FA code → Authenticate once →
Trusted device stored with attacker-controlled fields →
All future connections: 2FA bypassed via HWID match
Findings: 27 (trusted device persistence)
Impact: MEDIUM — one phished code → permanent 2FA bypass
```

---

## Key Innovation: These Chains Avoid Password Cracking

| Chain | Password Needed? | 2FA Needed? | Access Required |
|---|---|---|---|
| I (SwitchSides IPC) | **NO** | **NO** | Local (any user) |
| J (RS PK Injection) | **NO** | **NO** | Local (any user) |
| K (UUID Theft) | **NO** | **NO** | Network MITM |
| L (Pre-Auth SSRF) | **NO** | **NO** | Network (any) |
| M (Relay Race) | **NO** | **NO** | Network MITM |
| N (2FA Persistence) | Yes (once) | Yes (once) | Network (any) |

Chains I and J are the most critical: they require only local access to any user account and achieve full RustDesk access (including root shell on Linux) without knowing any password or 2FA code.
