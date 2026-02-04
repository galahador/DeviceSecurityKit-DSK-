# DeviceSecurityKit

A lightweight iOS security detection library for Swift. Detect jailbreak, debugger, emulator, and reverse engineering attempts with zero dependencies.

**Free & Open Source** — This library is completely free and will always remain free. No premium tiers, no hidden costs, no subscriptions. Ever.

# Features
🔒 Jailbreak Detection - Files, sandbox, URL schemes, symlinks
🐛 Debugger Detection - sysctl, ptrace
📱 Emulator Detection - Simulator environment detection
🔧 Reverse Engineering Detection - Frida, Substrate, libhooker, env vars
⚡ Lightweight - No dependencies, minimal footprint
🎯 Simple API - One-line checks or detailed results
🔄 Continuous Monitoring - Optional background monitoring

# Installation
Swift Package Manager
Add to your project via Xcode:

File → Add Package Dependencies
Enter URL: https://github.com/galahador/DeviceSecurityKit-DSK-.git
Click Add Package

# Swift Package Manager
swiftdependencies: [
    .package(url: "https://github.com/galahador/DeviceSecurityKit-DSK-.git", from: "0.1.0")
]

## Info.plist Configuration (Optional)
For URL scheme detection to work fully, add to your app's Info.plist:
xml<key>LSApplicationQueriesSchemes</key>
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

Note: Without this, URL scheme checks silently return false (no crash).

## Requirements
- iOS 15.0+
- Swift 5.9+
- Xcode 15.0+

### Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
MIT License

## Author
Created by galahador
