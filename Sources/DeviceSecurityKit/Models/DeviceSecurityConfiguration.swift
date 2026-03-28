import Foundation

public struct DeviceSecurityConfiguration: Equatable {
    public var jailbreakCheckEnabled: Bool
    public var debuggerCheckEnabled: Bool
    public var emulatorCheckEnabled: Bool
    public var reverseEngineeringCheckEnabled: Bool
    public var screenRecordingCheckEnabled: Bool
    public var hookDetectionEnabled: Bool
    public var pinningBypassDetectionEnabled: Bool
    public var vpnProxyDetectionEnabled: Bool

    public init(
        jailbreakCheckEnabled: Bool = true,
        debuggerCheckEnabled: Bool = true,
        emulatorCheckEnabled: Bool = true,
        reverseEngineeringCheckEnabled: Bool = true,
        screenRecordingCheckEnabled: Bool = true,
        hookDetectionEnabled: Bool = true,
        pinningBypassDetectionEnabled: Bool = true,
        vpnProxyDetectionEnabled: Bool = true
    ) {
        self.jailbreakCheckEnabled = jailbreakCheckEnabled
        self.debuggerCheckEnabled = debuggerCheckEnabled
        self.emulatorCheckEnabled = emulatorCheckEnabled
        self.reverseEngineeringCheckEnabled = reverseEngineeringCheckEnabled
        self.screenRecordingCheckEnabled = screenRecordingCheckEnabled
        self.hookDetectionEnabled = hookDetectionEnabled
        self.pinningBypassDetectionEnabled = pinningBypassDetectionEnabled
        self.vpnProxyDetectionEnabled = vpnProxyDetectionEnabled
    }
    
    // MARK: - Presets
    
    /// All checks enabled (default)
    public static let `default` = DeviceSecurityConfiguration()
    
    /// Only jailbreak detection
    public static let jailbreakOnly = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: true,
        debuggerCheckEnabled: false,
        emulatorCheckEnabled: false,
        reverseEngineeringCheckEnabled: false
    )
    
    /// Recommended for production apps
    public static let production = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: true,
        debuggerCheckEnabled: true,
        emulatorCheckEnabled: true,
        reverseEngineeringCheckEnabled: true
    )
    
    /// All checks disabled
    public static let disabled = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: false,
        debuggerCheckEnabled: false,
        emulatorCheckEnabled: false,
        reverseEngineeringCheckEnabled: false
    )
    
    // MARK: - Builder Pattern
    
    public func withJailbreakCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.jailbreakCheckEnabled = enabled
        return config
    }
    
    public func withDebuggerCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.debuggerCheckEnabled = enabled
        return config
    }
    
    public func withEmulatorCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.emulatorCheckEnabled = enabled
        return config
    }
    
    public func withReverseEngineeringCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.reverseEngineeringCheckEnabled = enabled
        return config
    }

    public func withScreenRecordingCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.screenRecordingCheckEnabled = enabled
        return config
    }

    public func withHookDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.hookDetectionEnabled = enabled
        return config
    }

    public func withPinningBypassDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.pinningBypassDetectionEnabled = enabled
        return config
    }

    public func withVPNProxyDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.vpnProxyDetectionEnabled = enabled
        return config
    }
}
