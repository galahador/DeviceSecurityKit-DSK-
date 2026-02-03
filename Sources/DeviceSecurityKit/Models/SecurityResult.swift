import Foundation

public struct SecurityResult: Equatable {
    public let threats: [SecurityThreat]
    
    public init(threats: [SecurityThreat] = []) {
        self.threats = threats
    }
    
    public var isSecure: Bool {
        return threats.isEmpty
    }
    
    public var isJailbroken: Bool {
        return threats.contains(.jailbreak)
    }
    
    public var isDebuggerAttached: Bool {
        return threats.contains(.debugger)
    }
    
    public var isEmulator: Bool {
        return threats.contains(.emulator)
    }
    
    public var isReverseEngineered: Bool {
        return threats.contains(.reverseEngineering)
    }
    
    public static let secure = SecurityResult(threats: [])
}
