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

## Scope Notes

- The `libs/hbb_common` submodule was not initialized, limiting review of the common library. The `password_security`, `config`, and `fs` modules referenced throughout the code could contain additional issues.
- Flutter/Dart UI code was not reviewed in depth (focus was on the Rust backend).
- This is a static analysis only; no dynamic testing or fuzzing was performed.
