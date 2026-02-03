import Foundation

public struct DeviceSecurityConfiguration: Equatable {
    public var jailbreakCheckEnabled: Bool
    public var debuggerCheckEnabled: Bool
    public var emulatorCheckEnabled: Bool
    public var reverseEngineeringCheckEnabled: Bool
    
    public init(
        jailbreakCheckEnabled: Bool = true,
        debuggerCheckEnabled: Bool = true,
        emulatorCheckEnabled: Bool = true,
        reverseEngineeringCheckEnabled: Bool = true
    ) {
        self.jailbreakCheckEnabled = jailbreakCheckEnabled
        self.debuggerCheckEnabled = debuggerCheckEnabled
        self.emulatorCheckEnabled = emulatorCheckEnabled
        self.reverseEngineeringCheckEnabled = reverseEngineeringCheckEnabled
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
}
