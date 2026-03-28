# DeviceSecurityKit

<p align="center">
  <img src="https://raw.githubusercontent.com/galahador/DeviceSecurityKit-DSK-/develop/DSK%20Image.png" width="340" alt="DeviceSecurityKit" />
</p>

> Lightweight iOS security detection. Zero dependencies. Always free.

[![Swift 5.9+](https://img.shields.io/badge/Swift-5.9+-F05138?style=flat&logo=swift&logoColor=white)](https://swift.org)
[![iOS 15.0+](https://img.shields.io/badge/iOS-15.0+-000000?style=flat&logo=apple&logoColor=white)](https://developer.apple.com/ios/)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![SPM Compatible](https://img.shields.io/badge/SPM-compatible-4BC51D?style=flat)](https://swift.org/package-manager/)

Detect jailbreak, debugger, emulator, and reverse engineering attempts with a single import.

---

## Features

| Detection | What it checks |
|-----------|---------------|
| 🔒 **Jailbreak** | Files, sandbox escape, URL schemes, symlinks |
| 🐛 **Debugger** | `sysctl`, `ptrace` |
| 📱 **Emulator** | Simulator environment variables |
| 🔧 **Reverse Engineering** | Frida, Substrate, libhooker, env vars |
| 🔄 **Monitoring** | Optional continuous background checks |
| 🖥️ **Screen Recording** | For Recording | 

---

## Installation

### Swift Package Manager (Xcode)

1. **File → Add Package Dependencies**
2. Enter the URL:
   ```
   https://github.com/galahador/DeviceSecurityKit-DSK-.git
   ```
3. Set version: `from: "0.3.0"`
4. Click **Add Package**

### `Package.swift`

```swift
dependencies: [
    .package(url: "https://github.com/galahador/DeviceSecurityKit-DSK-.git", from: "0.3.0")
]
```

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
