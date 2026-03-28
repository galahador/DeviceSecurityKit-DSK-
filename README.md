# DeviceSecurityKit

<p align="center">
  <img src="https://raw.githubusercontent.com/galahador/DeviceSecurityKit-DSK-/develop/DSK%20Image.png" width="340" alt="DeviceSecurityKit" />
</p>

> Lightweight iOS security detection. Zero dependencies. Always free.

[![Swift 5.9+](https://img.shields.io/badge/Swift-5.9+-F05138?style=flat&logo=swift&logoColor=white)](https://swift.org)
[![iOS 15.0+](https://img.shields.io/badge/iOS-15.0+-000000?style=flat&logo=apple&logoColor=white)](https://developer.apple.com/ios/)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![SPM Compatible](https://img.shields.io/badge/SPM-compatible-4BC51D?style=flat)](https://swift.org/package-manager/)

Detect jailbreak, debugger, emulator, screen recording, and reverse engineering attempts with a single import.

---

## Features

| Detection | What it checks |
|-----------|---------------|
| 🔒 **Jailbreak** | Files, sandbox escape, URL schemes, symlinks |
| 🐛 **Debugger** | `sysctl`, `ptrace` |
| 📱 **Emulator** | Simulator environment variables |
| 🔧 **Reverse Engineering** | Frida, Substrate, libhooker, env vars |
| 🎣 **Hook Detection** | Runtime method hooking |
| 📹 **Screen Recording** | Active recording/mirroring detection |
| 🔐 **Pinning Bypass** | Certificate pinning bypass detection |
| 🌐 **VPN / Proxy** | Network proxy and VPN detection |
| 🔄 **Monitoring** | Real-time continuous background checks |

---
## Installation

### Swift Package Manager (Xcode)

1. **File → Add Package Dependencies**
2. Enter the URL:
   ```
   https://github.com/galahador/DeviceSecurityKit-DSK-.git
   ```
3. Set version: `from: "0.9.0"`
4. Click **Add Package**

### `Package.swift`

```swift
dependencies: [
    .package(url: "https://github.com/galahador/DeviceSecurityKit-DSK-.git", from: "0.9.0")
]
```

---

## Usage

### Quick Check

```swift
let monitor = SecurityMonitor()
if monitor.isSecure() {
    // Safe to proceed
} else {
    let result = monitor.performCheck()
    print(result.threats)
}
```

### Continuous Monitoring

```swift
let monitor = SecurityMonitor()

monitor.onThreatDetected { threat in
    print("Threat detected: \(threat)")
}

monitor.onStatusChange { status in
    print("Status changed: \(status)")
}

monitor.startMonitoring()
```

---

## Configuration

### Presets

```swift
// All checks enabled (default)
monitor.configure(.default)

// Jailbreak only
monitor.configure(.jailbreakOnly)

// Recommended for production
monitor.configure(.production)

// Disable all checks
monitor.configure(.disabled)
```

### Builder Pattern

Fine-tune exactly what gets checked:

```swift
let config = SecurityConfiguration()
    .withJailbreakCheck(true)
    .withDebuggerCheck(true)
    .withEmulatorCheck(false)
    .withReverseEngineeringCheck(true)
    .withScreenRecordingCheck(true)
    .withHookDetection(true)
    .withPinningBypassDetection(true)
    .withVPNProxyDetection(false)

monitor.configure(config)
```

---

## API Reference

### `SecurityMonitor`

| Method | Returns | Description |
|--------|---------|-------------|
| `performCheck()` | `SecurityResult` | Run all configured checks once |
| `isSecure()` | `Bool` | Quick secure/not-secure check |
| `startMonitoring()` | `Void` | Begin continuous monitoring |
| `stopMonitoring()` | `Void` | Stop continuous monitoring |
| `configure(_:)` | `Void` | Update configuration |
| `onStatusChange(_:)` | `Void` | Callback on status change |
| `onThreatDetected(_:)` | `Void` | Callback on threat detection |

### `SecurityResult`

```swift
result.threats              // [SecurityThreat] — all detected threats
result.isSecure             // Bool
result.isJailbroken         // Bool
result.isDebuggerAttached   // Bool
// ... convenience properties for each threat type
```

### `SecurityThreat`

| Threat | Severity |
|--------|----------|
| `.jailbreak` | 🔴 Critical |
| `.reverseEngineering` | 🔴 Critical |
| `.hooked` | 🔴 Critical |
| `.pinningBypassed` | 🔴 Critical |
| `.debugger` | 🟠 High |
| `.screenRecording` | 🟠 High |
| `.emulator` | 🟡 Medium |
| `.vpnProxy` | 🟡 Medium |
| `.noThreat` | ✅ Normal |

### `SecurityStatus`

`.secure` · `.jailbroken` · `.debuggerAttached` · `.emulator` · `.reverseEngineered` · `.screenRecording` · `.hooked` · `.pinningBypassed` · `.vpnProxy` · `.compromised`

### `ThreatSeverity`

`.normal (0)` · `.low (1)` · `.medium (2)` · `.high (3)` · `.critical (4)`

---

## Info.plist Configuration

Add this to enable URL scheme detection. Without it, scheme checks silently return `false` — no crash.

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
    <string>undecimus</string>
    <string>checkra1n</string>
    <string>taurine</string>
    <string>odyssey</string>
    <string>dopamine</string>
</array>
```

---

## Requirements

- **iOS** 15.0+
- **Swift** 5.9+
- **Xcode** 15.0+

---

## Contributing

Issues and PRs are welcome. Open an issue first for major changes.

## License

[MIT](LICENSE) — Created by [galahador](https://github.com/galahador)

---

**Free & open source. No premium tiers, no subscriptions. Ever.**
