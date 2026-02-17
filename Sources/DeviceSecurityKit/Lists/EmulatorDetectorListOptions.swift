import Foundation

struct EmulatorDetectorListOptions {
    let simulatorPaths = [
        // Original paths
        "/System/Library/CoreServices/CoreSimulatorBridge.app",
        "/AppleInternal",
        
        // Additional comprehensive paths
        "/Applications/Xcode.app",
        "/usr/bin/xcrun",
        "/System/Library/Frameworks/CoreSimulator.framework",
        "/Library/Developer/CoreSimulator",
        "/private/var/containers/Bundle/Application",
        "/var/folders",
        "/System/Library/PrivateFrameworks/CoreSimulator.framework",
        "/Library/Developer/Xcode",
        "/usr/bin/simctl"
    ]
    
    let suspiciousEnvVars = [
        "SIMULATOR_DEVICE_NAME",
        "SIMULATOR_VERSION_INFO",
        "IPHONE_SIMULATOR_ROOT",
        "SIMULATOR_ROOT"
    ]
}
