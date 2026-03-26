import Foundation

struct EmulatorDetectorListOptions {
    let simulatorPaths = [
        "/System/Library/CoreServices/CoreSimulatorBridge.app",
        "/System/Library/Frameworks/CoreSimulator.framework",
        "/System/Library/PrivateFrameworks/CoreSimulator.framework",
        "/Library/Developer/CoreSimulator",
        "/Library/Developer/Xcode",
        "/Applications/Xcode.app",
        "/usr/bin/simctl",
        "/usr/bin/xcrun",
        "/AppleInternal",
        "/var/folders"
    ]
    
    let suspiciousEnvVars = [
        "SIMULATOR_DEVICE_NAME",
        "SIMULATOR_VERSION_INFO",
        "IPHONE_SIMULATOR_ROOT",
        "SIMULATOR_ROOT"
    ]
}
