import Foundation

public enum SecurityThreat: String, CaseIterable, Equatable {
    case jailbreak
    case debugger
    case emulator
    case reverseEngineering
    case screenRecording
    case hooked
    case pinningBypassed
    case noThreat

    public var description: String {
        switch self {
        case .jailbreak:
            return "Device is jailbroken"
        case .debugger:
            return "Debugger attached"
        case .emulator:
            return "Running in emulator"
        case .reverseEngineering:
            return "App tampering detected"
        case .screenRecording:
            return "Screen is being recorded"
        case .hooked:
            return "Security functions have been hooked"
        case .pinningBypassed:
            return "Certificate pinning bypass detected"
        case .noThreat:
            return "App is Secure"
        }
    }

    public var severity: ThreatSeverity {
        switch self {
        case .jailbreak:
            return .critical
        case .reverseEngineering:
            return .critical
        case .hooked:
            return .critical
        case .pinningBypassed:
            return .critical
        case .debugger:
            return .high
        case .screenRecording:
            return .high
        case .emulator:
            return .medium
        case .noThreat:
            return .normal
        }
    }
}

public enum ThreatSeverity: Int, Comparable {
    case normal = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4
    
    public static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}
