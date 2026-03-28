import Foundation

public enum SecurityStatus: Equatable {
    case secure
    case jailbroken
    case debuggerAttached
    case emulator
    case reverseEngineered
    case screenRecording
    case compromised

    public var isSecure: Bool {
        return self == .secure
    }

    public var description: String {
        switch self {
        case .secure:
            return "Device is secure"
        case .jailbroken:
            return "Device is jailbroken"
        case .debuggerAttached:
            return "Debugger is attached"
        case .emulator:
            return "Running in emulator"
        case .reverseEngineered:
            return "App has been tampered"
        case .screenRecording:
            return "Screen is being recorded"
        case .compromised:
            return "Device is compromised"
        }
    }
}
